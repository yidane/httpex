package httpex

import (
	"bytes"
	"fmt"
	"git.meizhu365.com/pub/qing/pkg/json"
	"github.com/ajg/form"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Request provides methods to incrementally build http.Request object,
// send it, and receive response.
type Request struct {
	httpError
	config     Config
	http       *http.Request
	path       string
	query      url.Values
	form       url.Values
	formBuf    *bytes.Buffer
	multipart  *multipart.Writer
	bodySetter string
	typeSetter string
	forceType  bool
}

//NewRequest
func newRequest(config Config, method, path string) (req *Request) {
	req = &Request{
		config: config,
		path:   path,
		httpError: httpError{
			lastErr: nil,
		},
	}

	if config.RequestFactory == nil {
		req.failf("config.RequestFactory == nil")
		return
	}

	if config.Client == nil {
		req.failf("config.Client == nil")
		return
	}

	//todo 如果baseUrl或者path中包含有query，应该怎么处理？目前处理方式为交给http包自己去处理
	//values, err := url.ParseQuery(config.BaseURL)
	//if err != nil {
	//	req.fail(err)
	//}
	//req.query = values

	hr, err := config.RequestFactory.NewRequest(method, config.BaseURL, nil)
	if err != nil {
		req.fail(err)
		return
	}

	req.http = hr
	return
}

// WithClient sets client.
//
// The new client overwrites Config.Client. It will be used once to send the
// Request and receive a response.
//
// Example:
//  req := NewRequest(config, "GET", "/path")
//  req.WithClient(&http.Client{
//    Transport: &http.Transport{
//      DisableCompression: true,
//    },
//  })
func (r *Request) WithClient(client Client) *Request {
	if r.failed() {
		return r
	}
	if client == nil {
		r.failf("unexpected nil client in WithClient")
		return r
	}
	r.config.Client = client
	return r
}

// WithPath substitutes named parameters in url path.
//
// value is converted to string using fmt.Sprint(). If there is no named
// parameter '{key}' in url path, failure is reported.
//
// Named parameters are case-insensitive.
//
// Example:
//  req := NewRequest(config, "POST", "/repos/{user}/{repo}")
//  req.WithPath("user", "gavv")
//  req.WithPath("repo", "http")
//  // path will be "/repos/gavv/http"
func (r *Request) WithPath(key string, value interface{}) *Request {
	if r.failed() {
		return r
	}

	//todo 替换{user}

	return r
}

// WithQuery adds query parameter to Request URL.
//
// value is converted to string using fmt.Sprint() and urlencoded.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithQuery("a", 123)
//  req.WithQuery("b", "foo")
//  // URL is now http://example.com/path?a=123&b=foo
func (r *Request) WithQuery(key string, value interface{}) *Request {
	if r.failed() {
		return r
	}
	if r.query == nil {
		r.query = make(url.Values)
	}
	r.query.Add(key, fmt.Sprint(value))
	return r
}

//// WithQueryObject adds multiple query parameters to Request URL.
////
//// object is converted to query string using github.com/google/go-querystring
//// if it's a struct or pointer to struct, or github.com/ajg/form otherwise.
////
//// Various object types are supported. Structs may contain "url" struct tag,
//// similar to "json" struct tag for json.Marshal().
////
//// Example:
////  type MyURL struct {
////      A int    `url:"a"`
////      B string `url:"b"`
////  }
////
////  req := NewRequest(config, "PUT", "http://example.com/path")
////  req.WithQueryObject(MyURL{A: 123, B: "foo"})
////  // URL is now http://example.com/path?a=123&b=foo
////
////  req := NewRequest(config, "PUT", "http://example.com/path")
////  req.WithQueryObject(map[string]interface{}{"a": 123, "b": "foo"})
////  // URL is now http://example.com/path?a=123&b=foo
//func (r *Request) WithQueryObject(object interface{}) *Request {
//	if r.chain.failed() {
//		return r
//	}
//	if object == nil {
//		return r
//	}
//	var (
//		q   url.Values
//		err error
//	)
//	if reflect.Indirect(reflect.ValueOf(object)).Kind() == reflect.Struct {
//		q, err = query.Values(object)
//		if err != nil {
//			r.chain.fail(err.Error())
//			return r
//		}
//	} else {
//		q, err = form.EncodeToValues(object)
//		if err != nil {
//			r.chain.fail(err.Error())
//			return r
//		}
//	}
//	if r.query == nil {
//		r.query = make(url.Values)
//	}
//	for k, v := range q {
//		r.query[k] = append(r.query[k], v...)
//	}
//	return r
//}

// WithQueryString parses given query string and adds it to Request URL.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithQuery("a", 11)
//  req.WithQueryString("b=22&c=33")
//  // URL is now http://example.com/path?a=11&bb=22&c=33
func (r *Request) WithQueryString(query string) *Request {
	if r.failed() {
		return r
	}
	v, err := url.ParseQuery(query)
	if err != nil {
		r.fail(err)
		return r
	}
	if r.query == nil {
		r.query = make(url.Values)
	}
	for k, v := range v {
		r.query[k] = append(r.query[k], v...)
	}
	return r
}

// WithURL sets Request URL.
//
// This URL overwrites Config.BaseURL. Request path passed to NewRequest()
// is appended to this URL, separated by slash if necessary.
//
// Example:
//  req := NewRequest(config, "PUT", "/path")
//  req.WithURL("http://example.com")
//  // URL is now http://example.com/path
func (r *Request) WithURL(urlStr string) *Request {
	if r.failed() {
		return r
	}
	if u, err := url.Parse(urlStr); err == nil {
		r.http.URL = u
	} else {
		r.fail(err)
	}
	return r
}

// WithHeaders adds given headers to Request.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithHeaders(map[string]string{
//      "Content-Type": "application/json",
//  })
func (r *Request) WithHeaders(headers map[string]string) *Request {
	if r.failed() {
		return r
	}
	for k, v := range headers {
		r.WithHeader(k, v)
	}
	return r
}

func (r *Request) WithMultiHeaders(headers map[string][]string) *Request {
	if r.failed() {
		return r
	}
	for k, v := range headers {
		for i := 0; i < len(v); i++ {
			r.WithHeader(k, v[i])
		}
	}
	return r
}

// WithHeader adds given single header to Request.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithHeader("Content-Type": "application/json")
func (r *Request) WithHeader(k, v string) *Request {
	if r.failed() {
		return r
	}
	switch http.CanonicalHeaderKey(k) {
	case "Host":
		r.http.Host = v
	case "Content-Type":
		if !r.forceType {
			delete(r.http.Header, "Content-Type")
		}
		r.forceType = true
		r.typeSetter = "WithHeader"
		r.http.Header.Add(k, v)
	default:
		r.http.Header.Add(k, v)
	}
	return r
}

func (r *Request) WithReferer(ref string) *Request {
	return r.WithHeader("Referer", ref)
}

func (r *Request) WithUserAgent(userAgent string) *Request {
	return r.WithHeader("User-Agent", userAgent)
}

func (r *Request) WithAccept(accept string) *Request {
	return r.WithHeader("Accept", accept)
}

func (r *Request) WithAcceptEncoding(acceptEncoding string) *Request {
	return r.WithHeader("Accept-Encoding", acceptEncoding)
}

func (r *Request) WithAcceptLanguage(acceptLanguage string) *Request {
	return r.WithHeader("Accept-Language", acceptLanguage)
}

func (r *Request) WithAuthorization(authorization string) *Request {
	return r.WithHeader("Authorization", authorization)
}

func (r *Request) WithKeepAlive() *Request {
	return r.WithHeader("Connection", "keep-alive")
}

func (r *Request) WithConnection(connection string) *Request {
	return r.WithHeader("Connection", connection)
}

func (r *Request) WithContentType(contentType string) *Request {
	return r.WithHeader("Content-Type", contentType)
}

func (r *Request) WithXRequestedWith(requestedWith string) *Request {
	return r.WithHeader("X-Requested-With", requestedWith)
}

func (r *Request) WithXMLHttpRequest() *Request {
	return r.WithHeader("X-Requested-With", "XMLHttpRequest")
}

// WithCookies adds given cookies to Request.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithCookies(map[string]string{
//      "foo": "aa",
//      "bar": "bb",
//  })
func (r *Request) WithCookies(cookies map[string]string) *Request {
	if r.failed() {
		return r
	}
	for k, v := range cookies {
		r.WithCookie(k, v)
	}
	return r
}

// WithCookie adds given single cookie to Request.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithCookie("name", "value")
func (r *Request) WithCookie(k, v string) *Request {
	if r.failed() {
		return r
	}
	r.http.AddCookie(&http.Cookie{
		Name:  k,
		Value: v,
	})
	return r
}

func (r *Request) WithHttpCookie(cookies ...*http.Cookie) *Request {
	if r.failed() {
		return r
	}

	for i := 0; i < len(cookies); i++ {
		cookie := cookies[i]
		if cookie == nil {
			continue
		}
		r.http.AddCookie(cookie)
	}

	return r
}

// WithBasicAuth sets the Request's Authorization header to use HTTP
// Basic Authentication with the provided username and password.
//
// With HTTP Basic Authentication the provided username and password
// are not encrypted.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithBasicAuth("john", "secret")
func (r *Request) WithBasicAuth(username, password string) *Request {
	if r.failed() {
		return r
	}
	r.http.SetBasicAuth(username, password)
	return r
}

func (r *Request) WithBearerToken(token string) *Request {
	return r.WithHeader("Authorization", fmt.Sprint("Bearer ", token))
}

// WithProto sets HTTP protocol version.
//
// proto should have form of "HTTP/{major}.{minor}", e.g. "HTTP/1.1".
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithProto("HTTP/2.0")
func (r *Request) WithProto(proto string) *Request {
	if r.failed() {
		return r
	}
	major, minor, ok := http.ParseHTTPVersion(proto)
	if !ok {
		r.failf("unexpected protocol version %q, expected \"HTTP/{major}.{minor}\"", proto)
		return r
	}
	r.http.ProtoMajor = major
	r.http.ProtoMinor = minor
	return r
}

// WithChunked enables chunked encoding and sets Request body reader.
//
// expect() will read all available data from given reader. Content-Length
// is not set, and "chunked" Transfer-Encoding is used.
//
// If protocol version is not at least HTTP/1.1 (required for chunked
// encoding), failure is reported.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/upload")
//  fh, _ := os.Open("data")
//  defer fh.Close()
//  req.WithHeader("Content-Type": "application/octet-stream")
//  req.WithChunked(fh)
func (r *Request) WithChunked(reader io.Reader) *Request {
	if r.failed() {
		return r
	}
	if !r.http.ProtoAtLeast(1, 1) {
		r.failf("chunked Transfer-Encoding requires at least \"HTTP/1.1\","+
			"but \"HTTP/%d.%d\" is enabled", r.http.ProtoMajor, r.http.ProtoMinor)
		return r
	}
	r.setBody("WithChunked", reader, -1, false)
	return r
}

// WithBytes sets Request body to given slice of bytes.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithHeader("Content-Type": "application/json")
//  req.WithBytes([]byte(`{"foo": 123}`))
func (r *Request) WithBytes(b []byte) *Request {
	if r.failed() {
		return r
	}
	if b == nil {
		r.setBody("WithBytes", nil, 0, false)
	} else {
		r.setBody("WithBytes", bytes.NewReader(b), len(b), false)
	}
	return r
}

// WithText sets Content-Type header to "text/plain; charset=utf-8" and
// sets body to given string.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithText("hello, world!")
func (r *Request) WithText(s string) *Request {
	if r.failed() {
		return r
	}
	r.setType("WithText", "text/plain; charset=utf-8", false)
	r.setBody("WithText", strings.NewReader(s), len(s), false)
	return r
}

// WithJSON sets Content-Type header to "application/json; charset=utf-8"
// and sets body to object, marshaled using json.Marshal().
//
// Example:
//  type MyJSON struct {
//      Foo int `json:"foo"`
//  }
//
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithJSON(MyJSON{Foo: 123})
//
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithJSON(map[string]interface{}{"foo": 123})
func (r *Request) WithJSON(object interface{}) *Request {
	if r.failed() {
		return r
	}
	b, err := json.Marshal(object)
	if err != nil {
		r.fail(err)
		return r
	}

	r.setType("WithJSON", "application/json; charset=utf-8", false)
	r.setBody("WithJSON", bytes.NewReader(b), len(b), false)

	return r
}

// WithForm sets Content-Type header to "application/x-www-form-urlencoded"
// or (if WithMultipart() was called) "multipart/form-data", converts given
// object to url.Values using github.com/ajg/form, and adds it to Request body.
//
// Various object types are supported, including maps and structs. Structs may
// contain "form" struct tag, similar to "json" struct tag for json.Marshal().
// See https://github.com/ajg/form for details.
//
// Multiple WithForm(), WithFormField(), and WithFile() calls may be combined.
// If WithMultipart() is called, it should be called first.
//
// Example:
//  type MyForm struct {
//      Foo int `form:"foo"`
//  }
//
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithForm(MyForm{Foo: 123})
//
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithForm(map[string]interface{}{"foo": 123})
func (r *Request) WithForm(object interface{}) *Request {
	if r.failed() {
		return r
	}

	f, err := form.EncodeToValues(object)
	if err != nil {
		r.fail(err)
		return r
	}

	if r.multipart != nil {
		r.setType("WithForm", "multipart/form-data", false)

		var keys []string
		for k := range f {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := r.multipart.WriteField(k, f[k][0]); err != nil {
				r.fail(err)
				return r
			}
		}
	} else {
		r.setType("WithForm", "application/x-www-form-urlencoded", false)

		if r.form == nil {
			r.form = make(url.Values)
		}
		for k, v := range f {
			r.form[k] = append(r.form[k], v...)
		}
	}

	return r
}

// WithFormField sets Content-Type header to "application/x-www-form-urlencoded"
// or (if WithMultipart() was called) "multipart/form-data", converts given
// value to string using fmt.Sprint(), and adds it to Request body.
//
// Multiple WithForm(), WithFormField(), and WithFile() calls may be combined.
// If WithMultipart() is called, it should be called first.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithFormField("foo", 123).
//      WithFormField("bar", 456)
func (r *Request) WithFormField(key string, value interface{}) *Request {
	if r.failed() {
		return r
	}
	if r.multipart != nil {
		r.setType("WithFormField", "multipart/form-data", false)

		err := r.multipart.WriteField(key, fmt.Sprint(value))
		if err != nil {
			r.fail(err)
			return r
		}
	} else {
		r.setType("WithFormField", "application/x-www-form-urlencoded", false)

		if r.form == nil {
			r.form = make(url.Values)
		}
		r.form[key] = append(r.form[key], fmt.Sprint(value))
	}
	return r
}

// WithFile sets Content-Type header to "multipart/form-data", reads given
// file and adds its contents to Request body.
//
// If reader is given, it's used to read file contents. Otherwise, os.Open()
// is used to read a file with given path.
//
// Multiple WithForm(), WithFormField(), and WithFile() calls may be combined.
// WithMultipart() should be called before WithFile(), otherwise WithFile()
// fails.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithFile("avatar", "./john.png")
//
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  fh, _ := os.Open("./john.png")
//  req.WithMultipart().
//      WithFile("avatar", "john.png", fh)
//  fh.Close()
func (r *Request) WithFile(key, path string, reader ...io.Reader) *Request {
	if r.failed() {
		return r
	}

	r.setType("WithFile", "multipart/form-data", false)

	if r.multipart == nil {
		r.failf("WithFile requires WithMultipart to be called first")
		return r
	}

	wr, err := r.multipart.CreateFormFile(key, path)
	if err != nil {
		r.fail(err)
		return r
	}

	var rd io.Reader
	if len(reader) != 0 && reader[0] != nil {
		rd = reader[0]
	} else {
		f, err := os.Open(path)
		if err != nil {
			r.fail(err)
			return r
		}
		rd = f
		defer func() {
			err := f.Close()
			//todo
			log.Println(err)
		}()
	}

	if _, err := io.Copy(wr, rd); err != nil {
		r.fail(err)
		return r
	}

	return r
}

// WithFileBytes is like WithFile, but uses given slice of bytes as the
// file contents.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  fh, _ := os.Open("./john.png")
//  b, _ := ioutil.ReadAll(fh)
//  req.WithMultipart().
//      WithFileBytes("avatar", "john.png", b)
//  fh.Close()
func (r *Request) WithFileBytes(key, path string, data []byte) *Request {
	if r.failed() {
		return r
	}
	return r.WithFile(key, path, bytes.NewReader(data))
}

// WithMultipart sets Content-Type header to "multipart/form-data".
//
// After this call, WithForm() and WithFormField() switch to multipart
// form instead of urlencoded form.
//
// If WithMultipart() is called, it should be called before WithForm(),
// WithFormField(), and WithFile().
//
// WithFile() always requires WithMultipart() to be called first.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithMultipart().
//      WithForm(map[string]interface{}{"foo": 123})
func (r *Request) WithMultipart() *Request {
	if r.failed() {
		return r
	}

	r.setType("WithMultipart", "multipart/form-data", false)

	if r.multipart == nil {
		r.formBuf = new(bytes.Buffer)
		r.multipart = multipart.NewWriter(r.formBuf)
		r.setBody("WithMultipart", r.formBuf, 0, false)
	}

	return r
}

//WithFunc can set any value with customer func
func (r *Request) WithFunc(f func(req *Request) *Request) *Request {
	if f != nil {
		return f(r)
	}

	return r
}

// expect constructs http.Request, sends it, receives http.response, and
// returns a new response object to inspect received response.
//
// Request is sent using Config.Client interface, or Config.Dialer interface
// in case of WebSocket Request.
//
// Example:
//  req := NewRequest(config, "PUT", "http://example.com/path")
//  req.WithJSON(map[string]interface{}{"foo": 123})
//  resp := req.expect()
//  resp.Status(http.StatusOK)
func (r *Request) Do() *response {
	resp := r.roundTrip()

	if resp == nil {
		return makeResponse(responseOpts{
			config:    r.config,
			httpError: r.httpError, //传递过去错误信息
		})
	}

	return resp
}

func (r *Request) roundTrip() *response {
	if !r.encodeRequest() {
		return nil
	}

	start := time.Now()

	httpResp := r.sendRequest()
	elapsed := time.Since(start)

	if httpResp == nil {
		return nil
	}

	return makeResponse(responseOpts{
		config:    r.config,
		httpError: r.httpError,
		response:  httpResp,
		rtt:       &elapsed,
	})
}

func (r *Request) encodeRequest() bool {
	if r.failed() {
		return false
	}

	r.http.URL.Path = concatPaths(r.http.URL.Path, r.path)

	if r.query != nil {
		r.http.URL.RawQuery = r.query.Encode()
	}

	if r.multipart != nil {
		if err := r.multipart.Close(); err != nil {
			r.fail(err)
			return false
		}

		r.setType("expect", r.multipart.FormDataContentType(), true)
		r.setBody("expect", r.formBuf, r.formBuf.Len(), true)
	} else if r.form != nil {
		s := r.form.Encode()
		r.setBody("WithForm or WithFormField", strings.NewReader(s), len(s), false)
	}

	return true
}

func (r *Request) sendRequest() *http.Response {
	if r.failed() {
		return nil
	}

	resp, err := r.config.Client.Do(r.http)

	if err != nil {
		r.fail(err)
		return nil
	}

	return resp
}

func (r *Request) setType(newSetter, newType string, overwrite bool) {
	if r.forceType {
		return
	}

	if !overwrite {
		previousType := r.http.Header.Get("Content-Type")

		if previousType != "" && previousType != newType {
			r.failf("ambiguous Request \"Content-Type\" header values:\n %q (set by %s) \n and:\n %q (wanted by %s)",
				previousType, r.typeSetter, newType, newSetter)
			return
		}
	}

	r.typeSetter = newSetter
	r.http.Header["Content-Type"] = []string{newType}
}

func (r *Request) setBody(setter string, reader io.Reader, len int, overwrite bool) {
	if !overwrite && r.bodySetter != "" {
		r.failf("ambiguous Request body contents:\n  set by %s\n  overwritten by %s", r.bodySetter, setter)
		return
	}

	if len > 0 && reader == nil {
		r.failf("the length Request body is invalid")
		return
	}

	if reader == nil {
		r.http.Body = nil
		r.http.ContentLength = 0
	} else {
		r.http.Body = ioutil.NopCloser(reader)
		r.http.ContentLength = int64(len)
	}

	r.bodySetter = setter
}

func concatPaths(a, b string) string {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	a = strings.TrimSuffix(a, "/")
	b = strings.TrimPrefix(b, "/")
	return fmt.Sprint(a, "/", b)
}
