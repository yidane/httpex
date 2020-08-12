package httpex

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	var (
		d        time.Duration
		response = New("https://www.baidu.com").GET("").Do().Duration(&d)
	)
	t.Log(d.Seconds())
	_, err := response.Html()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRangNumber(t *testing.T) {
	numberText, err := New("https://www.random.org/integers/").
		GET("").
		WithQuery("num", 1).
		WithQuery("min", 1).
		WithQuery("max", 100).
		WithQuery("col", 1).
		WithQuery("base", 10).
		WithQuery("format", "plain").
		WithQuery("rnd", "new").
		Do().
		Text()

	if err != nil {
		t.Fatal(err)
	}

	t.Log(numberText)
}

func TestHttpGet(t *testing.T) {
	jsonText, err := New("http://httpbin.org/?key0=2").
		GET("get").
		WithQuery("key", 123).
		Do().
		JSON()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(jsonText))
}

func TestHttpPost(t *testing.T) {
	jsonText, err := New("http://httpbin.org/?key0=2").
		POST("post").
		WithQuery("key", 123).
		Do().
		JSON()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(jsonText))
}

func TestHttpPut(t *testing.T) {
	jsonText, err := New("http://httpbin.org/?key0=2").
		PUT("put").
		WithQuery("key", 123).
		Do().
		JSON()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(jsonText))
}

func TestHttpHead(t *testing.T) {
	headResponse := New("http://httpbin.org/?key0=2").
		HEAD("headers").
		WithQuery("key", 123).
		Do()

	err := headResponse.LastError()
	if err != nil {
		t.Fatal(err)
	}
}

func TestHttpDelete(t *testing.T) {
	jsonText, err := New("http://httpbin.org/?key0=2").
		DELETE("delete").
		WithQuery("key", 123).
		Do().
		JSON()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(jsonText))
}
