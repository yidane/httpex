package httpex

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
)

type httpError struct {
	lastErr error
}

func (r *httpError) failf(format string, v ...interface{}) {
	r.lastErr = fmt.Errorf(format, v...)
}

func (r *httpError) fail(err error) {
	r.lastErr = err
}

func (r *httpError) failed() bool {
	return r.lastErr != nil
}

func (r *httpError) LastError() error {
	return r.lastErr
}

// expect is a toplevel object that contains user Config and allows
// to construct Request objects.
type expect struct {
	config   Config
	builders []func(*Request)
	matchers []func(*response)
}

// Config contains various settings.
type Config struct {
	// BaseURL is a URL to prepended to all Request. My be empty. If
	// non-empty, trailing slash is allowed but not required and is
	// appended automatically.
	BaseURL string

	// RequestFactory is used to pass in a custom *http.Request generation func.
	// May be nil.
	//
	// You can use defaultRequestFactory, or provide custom implementation.
	// Useful for Google App Engine testing for example.
	RequestFactory RequestFactory

	// Client is used to send http.Request and receive http.response.
	// Should not be nil.
	//
	// You can use http.DefaultClient or http.Client, or provide
	// custom implementation.
	Client Client
}

// RequestFactory is used to create all http.Request objects.
type RequestFactory interface {
	NewRequest(method, urlStr string, body io.Reader) (*http.Request, error)
}

// Client is used to send http.Request and receive http.response.
// http.Client implements this interface.
//
// Binder and FastBinder may be used to obtain this interface implementation.
//
// Example:
//  httpBinderClient := &http.Client{
//    Transport: http.NewBinder(HTTPHandler),
//  }
//  fastBinderClient := &http.Client{
//    Transport: http.NewFastBinder(FastHTTPHandler),
//  }
type Client interface {
	// Do sends Request and returns response.
	Do(*http.Request) (*http.Response, error)
}

// defaultRequestFactory is the default RequestFactory implementation which just
// calls http.NewRequest.
type defaultRequestFactory struct{}

// NewRequest implements RequestFactory.NewRequest.
func (defaultRequestFactory) NewRequest(method, urlStr string, body io.Reader) (*http.Request, error) {
	return http.NewRequest(method, urlStr, body)
}

var defaultRequestFactoryInstance = defaultRequestFactory{}

// DefaultRequestFactory return a defaultRequestFactory Instance.
func DefaultRequestFactory() RequestFactory {
	return defaultRequestFactoryInstance
}

// New returns a new expect object.
//
// baseURL specifies URL to prepended to all Request. My be empty. If non-empty,
// trailing slash is allowed but not required and is appended automatically.
//
// New is a shorthand for WithConfig. It uses:
//  - CompactPrinter as Printer, with testing.TB as Logger
//  - AssertReporter as Reporter
//  - defaultRequestFactory as RequestFactory
//
// Client is set to a default client with a non-nil Jar:
//  &http.Client{
//      Jar: http.NewJar(),
//  }
//
// Example:
//  func TestSomething(t *testing.T) {
//      e := http.New(t, "http://example.com/")
//
//      e.GET("/path").
//          expect().
//          Status(http.StatusOK)
//  }
func New(baseURL string) *expect {
	return WithConfig(Config{
		BaseURL: baseURL,
	})
}

// WithConfig returns a new expect object with given config.
//
// If RequestFactory is nil, it's set to a defaultRequestFactory instance.
//
// If Client is nil, it's set to a default client with a non-nil Jar:
//  &http.Client{
//      Jar: http.NewJar(),
//  }
//
// Example:
//  func TestWithConfig(t *testing.T) {
//      e := http.WithConfig(http.Config{
//          BaseURL:  "http://example.com/",
//          Client:   &http.Client{
//              Transport: http.NewBinder(myHandler()),
//              Jar:       http.NewJar(),
//          },
//      })
//
//      e.GET("/path").
//          expect().
//          Status(http.StatusOK)
//  }
func WithConfig(config Config) *expect {
	if config.RequestFactory == nil {
		config.RequestFactory = DefaultRequestFactory()
	}

	if config.Client == nil {
		config.Client = &http.Client{
			Jar: newJar(),
		}
	}

	return &expect{
		config: config,
	}
}

// NewJar returns a new http.CookieJar.
//
// Note that this jar ignores cookies when Request url is empty.
func newJar() http.CookieJar {
	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		panic(err)
	}
	return jar
}

// Builder returns a copy of expect instance with given builder attached to it.
// Returned copy contains all previously attached builders plus a new one.
// Builders are invoked from Request method, after constructing every new Request.
//
// Example:
//  e := http.New(t, "http://example.com")
//
//  token := e.POST("/login").WithForm(Login{"ford", "betelgeuse7"}).
//      expect().
//      Status(http.StatusOK).JSON().Object().Value("token").String().Raw()
//
//  auth := e.Builder(func (req *http.Request) {
//      req.WithHeader("Authorization", "Bearer "+token)
//  })
//
//  auth.GET("/restricted").
//     expect().
//     Status(http.StatusOK)
func (e *expect) Builder(builder func(*Request)) *expect {
	ret := *e
	ret.builders = append(e.builders, builder)
	return &ret
}

// Matcher returns a copy of expect instance with given matcher attached to it.
// Returned copy contains all previously attached matchers plus a new one.
// Matchers are invoked from Request.expect method, after retrieving a new response.
//
// Example:
//  e := http.New(t, "http://example.com")
//
//  m := e.Matcher(func (resp *http.response) {
//      resp.Header("API-Version").NotEmpty()
//  })
//
//  m.GET("/some-path").
// 	    expect().
// 	    Status(http.StatusOK)
//
//  m.GET("/bad-path").
// 	    expect().
// 	    Status(http.StatusNotFound)
func (e *expect) Matcher(matcher func(*response)) *expect {
	ret := *e
	ret.matchers = append(e.matchers, matcher)
	return &ret
}

// Request returns a new Request object.
// Arguments a similar to NewRequest.
// After creating Request, all builders attached to expect object are invoked.
// See Builder.
func (e *expect) Request(method, path string) *Request {
	req := newRequest(e.config, method, path)

	for _, builder := range e.builders {
		builder(req)
	}

	return req
}

// OPTIONS is a shorthand for e.Request("OPTIONS", path).
func (e *expect) OPTIONS(path string) *Request {
	return e.Request("OPTIONS", path)
}

// HEAD is a shorthand for e.Request("HEAD", path).
func (e *expect) HEAD(path string) *Request {
	return e.Request("HEAD", path)
}

// GET is a shorthand for e.Request("GET", path).
func (e *expect) GET(path string) *Request {
	return e.Request("GET", path)
}

// POST is a shorthand for e.Request("POST", path).
func (e *expect) POST(path string) *Request {
	return e.Request("POST", path)
}

// PUT is a shorthand for e.Request("PUT", path).
func (e *expect) PUT(path string) *Request {
	return e.Request("PUT", path)
}

// PATCH is a shorthand for e.Request("PATCH", path).
func (e *expect) PATCH(path string) *Request {
	return e.Request("PATCH", path)
}

// DELETE is a shorthand for e.Request("DELETE", path).
func (e *expect) DELETE(path string) *Request {
	return e.Request("DELETE", path)
}
