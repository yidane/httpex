package httpex

import (
	"bytes"
	"fmt"
	"git.meizhu365.com/pub/qing/pkg/json"
	"github.com/ajg/form"
	"io/ioutil"
	"mime"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// response provides methods to inspect attached http.response object.
type response struct {
	httpError
	config  Config
	resp    *http.Response
	content []byte
	cookies []*http.Cookie
	rtt     *time.Duration
}

type responseOpts struct {
	httpError
	config   Config
	response *http.Response
	rtt      *time.Duration
}

func makeResponse(opts responseOpts) *response {
	var (
		content []byte
		cookies []*http.Cookie
		err     error
	)
	if opts.response != nil {
		content, err = getContent(opts.response)
		cookies = opts.response.Cookies()
	} else {
		err = opts.lastErr
	}
	return &response{
		config:    opts.config,
		httpError: httpError{lastErr: err},
		resp:      opts.response,
		content:   content,
		cookies:   cookies,
		rtt:       opts.rtt,
	}
}

func getContent(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return []byte{}, nil
	}

	return ioutil.ReadAll(resp.Body)
}

func (r *response) ContinueWithOPTIONS(path string) *Request {
	return WithConfig(r.config).
		OPTIONS(path).
		WithHttpCookie(r.Cookies()...).
		WithMultiHeaders(r.Headers())
}

func (r *response) ContinueWithHEAD(path string) *Request {
	return WithConfig(r.config).
		HEAD(path).
		WithHttpCookie(r.Cookies()...).
		WithMultiHeaders(r.Headers())
}

//Continue return next Request with the last cookies and headers
func (r *response) ContinueWithGET(path string) *Request {
	return WithConfig(r.config).
		GET(path).
		WithHttpCookie(r.Cookies()...).
		WithMultiHeaders(r.Headers())
}

func (r *response) ContinueWithPOST(path string) *Request {
	return WithConfig(r.config).
		POST(path).
		WithHttpCookie(r.Cookies()...).
		WithMultiHeaders(r.Headers())
}

func (r *response) ContinueWithPUT(path string) *Request {
	return WithConfig(r.config).
		PUT(path).
		WithHttpCookie(r.Cookies()...).
		WithMultiHeaders(r.Headers())
}

func (r *response) ContinueWithPATCH(path string) *Request {
	return WithConfig(r.config).
		PATCH(path).
		WithHttpCookie(r.Cookies()...).
		WithMultiHeaders(r.Headers())
}

func (r *response) ContinueWithDELETE(path string) *Request {
	return WithConfig(r.config).
		DELETE(path).
		WithHttpCookie(r.Cookies()...).
		WithMultiHeaders(r.Headers())
}

func (r *response) ContinueWith(method, path string, f func(req *Request, res *response)) *Request {
	var newRequest = newRequest(r.config, method, path)

	if f != nil {
		f(newRequest, r)
	}

	return newRequest
}

//Duration returns duration of the http exec time
func (r *response) Duration(d *time.Duration) *response {
	if d == nil {
		return r
	}

	if r.failed() || r.missedResponse() {
		return r
	}

	*d = *r.rtt
	return r
}

// Raw returns underlying http.response object.
// This is the value originally passed to NewResponse.
func (r *response) Raw() *http.Response {
	return r.resp
}

// Status succeeds if response equal StatusOK.
func (r *response) StatusOk() *response {
	if r.failed() || r.missedResponse() {
		return r
	}

	return r.Status(http.StatusOK)
}

// Status succeeds if response contains given status code.
//
// Example:
//  resp := NewResponse(t, response)
//  resp.Status(http.StatusOK)
func (r *response) Status(status int) *response {
	if r.failed() || r.missedResponse() {
		return r
	}

	if r.resp.StatusCode != status {
		r.failf("expected status %d but got: %d", status, r.resp.StatusCode)
	}

	return r
}

// StatusRange succeeds if response status belongs to given range.
func (r *response) StatusRange(leftStatus, rightStatus int) *response {
	if r.failed() || r.missedResponse() {
		return r
	}

	if r.resp.StatusCode < leftStatus || rightStatus < r.resp.StatusCode {
		r.failf("expected status from range %d to %d but got: %d", leftStatus, rightStatus, r.resp.StatusCode)
	}

	return r
}

// Headers returns a new Object that may be used to inspect header map.
//
// Example:
//  resp := NewResponse(t, response)
//  resp.Headers().Value("Content-Type").String().Equal("application-json")
func (r *response) Headers() map[string][]string {
	if r.failed() || r.missedResponse() {
		return nil
	}
	return r.resp.Header
}

// Header returns a new String object that may be used to inspect given header.
//
// Example:
//  resp := NewResponse(t, response)
//  resp.Header("Content-Type").Equal("application-json")
//  resp.Header("Date").DateTime().Le(time.Now())
func (r *response) Header(key string) string {
	if r.failed() || r.missedResponse() {
		return ""
	}

	value := ""
	if !r.failed() {
		value = r.resp.Header.Get(key)
	}
	return value
}

// Cookies returns a new Array object with all cookie names set by this response.
// Returned Array contains a String value for every cookie name.
//
// Note that this returns only cookies set by Set-Cookie headers of this response.
// It doesn't return session cookies from previous responses, which may be stored
// in a cookie jar.
//
// Example:
//  resp := NewResponse(t, response)
//  resp.Cookies().Contains("session")
func (r *response) Cookies() []*http.Cookie {
	if r.failed() {
		return nil
	}

	var (
		cookies         []*http.Cookie
		responseCookies = r.resp.Cookies()
	)

	for i := 0; i < len(responseCookies); i++ {
		var cookie = responseCookies[i]
		cookies = append(cookies, cookie)
	}

	return cookies
}

// Cookie returns a new Cookie object that may be used to inspect given cookie
// set by this response.
//
// Note that this returns only cookies set by Set-Cookie headers of this response.
// It doesn't return session cookies from previous responses, which may be stored
// in a cookie jar.
//
// Example:
//  resp := NewResponse(t, response)
//  resp.Cookie("session").Domain().Equal("example.com")
func (r *response) Cookie(name string) []*http.Cookie {
	if r.failed() {
		return nil
	}
	var cookies []*http.Cookie
	for i := 0; i < len(r.cookies); i++ {
		var cookie = r.cookies[i]
		if cookie.Name == name {
			cookies = append(cookies, cookie)
		}
	}

	return cookies
}

// Body returns a new String object that may be used to inspect response body.
func (r *response) Body() []byte {
	return r.content
}

// NoContent succeeds if response contains empty Content-Type header and empty body.
func (r *response) NoContent() *response {
	if r.failed() || r.missedResponse() {
		return r
	}

	contentType := r.resp.Header.Get("Content-Type")

	r.checkEqual("\"Content-Type\" header", "", contentType)
	r.checkEqual("body", "", string(r.content))

	return r
}

// ContentType succeeds if response contains Content-Type header with given
// media type and charset.
//
// If charset is omitted, and mediaType is non-empty, Content-Type header
// should contain empty or utf-8 charset.
//
// If charset is omitted, and mediaType is also empty, Content-Type header
// should contain no charset.
//func (r *response) ContentType(mediaType string, charset ...string) *response {
//	r.checkContentType(mediaType, charset...)
//	return r
//}

// ContentEncoding succeeds if response has exactly given Content-Encoding list.
// Common values are empty, "gzip", "compress", "deflate", "identity" and "br".
func (r *response) ContentEncoding(encoding ...string) *response {
	if r.failed() || r.missedResponse() {
		return r
	}
	r.checkEqual("\"Content-Encoding\" header", encoding, r.resp.Header["Content-Encoding"])
	return r
}

// TransferEncoding succeeds if response contains given Transfer-Encoding list.
// Common values are empty, "chunked" and "identity".
func (r *response) TransferEncoding(encoding ...string) *response {
	if r.failed() || r.missedResponse() {
		return r
	}
	r.checkEqual("\"Transfer-Encoding\" header", encoding, r.resp.TransferEncoding)
	return r
}

//// ContentOpts define parameters for matching the response content parameters.
//type ContentOpts struct {
//	// The media type Content-Type part, e.g. "application/json"
//	MediaType string
//	// The character set Content-Type part, e.g. "utf-8"
//	Charset string
//}

//func (r *response) MediaType(opts []string) {
//
//}

// Text returns a new String object that may be used to inspect response body.
//
// Text succeeds if response contains "text/plain" Content-Type header
// with empty or "utf-8" charset.
//
// Example:
//  resp := NewResponse(t, response)
//  resp.Text().Equal("hello, world!")
//  resp.Text(ContentOpts{
//    MediaType: "text/plain",
//  }).Equal("hello, world!")
func (r *response) Text() (string, error) {
	var content string

	if r.failed() || r.missedResponse() {
		return content, r.lastErr
	}

	if err := r.contentType("text/plain"); err != nil {
		return content, err
	}

	content = string(r.content)
	return content, nil
}

func (r *response) Html() (string, error) {
	var content string

	if r.failed() || r.missedResponse() {
		return content, r.lastErr
	}

	if err := r.contentType("text/html"); err != nil {
		return content, err
	}

	content = string(r.content)
	return content, nil
}

// Form returns a new Object that may be used to inspect form contents
// of response.
//
// Form succeeds if response contains "application/x-www-form-urlencoded"
// Content-Type header and if form may be decoded from response body.
// Decoding is performed using https://github.com/ajg/form.
//
// Example:
//  resp := NewResponse(t, response)
//  resp.Form().Value("foo").Equal("bar")
//  resp.Form(ContentOpts{
//    MediaType: "application/x-www-form-urlencoded",
//  }).Value("foo").Equal("bar")
func (r *response) Form() (map[string]interface{}, error) {
	if r.failed() || r.missedResponse() {
		return nil, r.lastErr
	}

	if err := r.contentType("application/x-www-form-urlencoded"); err != nil {
		return nil, err
	}

	decoder := form.NewDecoder(bytes.NewReader(r.content))

	var object map[string]interface{}
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}

	return object, nil
}

// JSON returns a new Value object that may be used to inspect JSON contents
// of response.
//
// JSON succeeds if response contains "application/json" Content-Type header
// with empty or "utf-8" charset and if JSON may be decoded from response body.
//
// Example:
//  resp := NewResponse(t, response)
//  resp.JSON().Array().Elements("foo", "bar")
//  resp.JSON(ContentOpts{
//    MediaType: "application/json",
//  }).Array.Elements("foo", "bar")
func (r *response) JSON() ([]byte, error) {
	if r.failed() || r.missedResponse() {
		return r.content, r.lastErr
	}

	if err := r.contentType("application/json"); err != nil {
		return r.content, err
	}

	if !json.Valid(r.content) {
		return r.content, fmt.Errorf("response data is not a valid JSON encoding")
	}

	return r.content, nil
}

func (r *response) JsonUnmarshal(v interface{}) ([]byte, error) {
	jsonData, err := r.JSON()
	if err != nil {
		return jsonData, err
	}

	if v == nil {
		return jsonData, fmt.Errorf("argument v is nil")
	}

	return jsonData, json.Unmarshal(jsonData, v)
}

//Unmarshal can unmarshal data to object both json and xml
func (r *response) Unmarshal(v interface{}) error {

	return nil
}

var (
	jsonp = regexp.MustCompile(`^\s*([^\s(]+)\s*\((.*)\)\s*;*\s*$`)
)

// JSONP returns a new Value object that may be used to inspect JSONP contents
// of response.
//
// JSONP succeeds if response contains "application/javascript" Content-Type
// header with empty or "utf-8" charset and response body of the following form:
//  callback(<valid json>);
// or:
//  callback(<valid json>)
//
// Whitespaces are allowed.
//
// Example:
//  resp := NewResponse(t, response)
//  resp.JSONP("myCallback").Array().Elements("foo", "bar")
//  resp.JSONP("myCallback", ContentOpts{
//    MediaType: "application/javascript",
//  }).Array.Elements("foo", "bar")
func (r *response) JSONP(callback string) ([]byte, error) {
	if r.failed() || r.missedResponse() {
		return nil, r.lastErr
	}

	if err := r.contentType("application/javascript"); err != nil {
		return nil, err
	}

	m := jsonp.FindSubmatch(r.content)
	if len(m) != 3 || string(m[1]) != callback {
		return nil, fmt.Errorf("expected JSONP body in form of: \"%s(<valid json>)\"but got: %q", callback, string(r.content))
	}

	return m[2], nil
}

func (r *response) Charset(expectedCharset string) *response {
	if r.failed() || r.missedResponse() {
		return r
	}

	err := r.charset(expectedCharset)
	if err != nil {
		r.fail(err)
	}

	return r
}

func (r *response) charset(expectedCharset string) error {
	contentType := r.resp.Header.Get("Content-Type")

	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Errorf("got invalid \"Content-Type\" header %q", contentType)
	}

	charset := params["charset"]

	if len(expectedCharset) == 0 {
		if charset != "" && !strings.EqualFold(charset, "utf-8") {
			return fmt.Errorf("expected \"Content-Type\" header with \"utf-8\" or empty charset,but got %q", charset)
		}
	} else {
		if !strings.EqualFold(charset, expectedCharset) {
			return fmt.Errorf("expected \"Content-Type\" header with %q charset,but got %q", expectedCharset, charset)
		}
	}

	return nil
}

func (r *response) ContentType(expectedType string) *response {
	if r.failed() || r.missedResponse() {
		return r
	}

	err := r.contentType(expectedType)
	if err != nil {
		r.fail(err)
	}

	return r
}

func (r *response) contentType(expectedContentType string) error {
	if r.failed() || r.missedResponse() {
		return r.lastErr
	}

	contentType := r.resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)

	if err != nil {
		return fmt.Errorf("got invalid \"Content-Type\" header %q", contentType)
	}

	if mediaType != expectedContentType {
		return fmt.Errorf("expected \"Content-Type\" header with %q media type,but got %q", expectedContentType, mediaType)
	}

	return nil
}

func (r *response) checkEqual(what string, expected, actual interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		r.failf("expected %s equal to:%s but got: %s", what, dumpValue(expected), dumpValue(actual))
	}
}

func (r *response) missedResponse() bool {
	if r.resp == nil {
		r.failf("response is nil, do you call Expect method first")
		return true
	}

	return false
}

func dumpValue(value interface{}) string {
	b, err := json.MarshalIndent(value, " ", "  ")
	if err != nil {
		return " " + fmt.Sprintf("%#v", value)
	}
	return " " + string(b)
}
