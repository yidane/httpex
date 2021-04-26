package httpex

import (
	"net/http"
	"testing"
)

func TestResponse_Status(t *testing.T) {
	result := New("https://www.baidu.com").GET("").Do()
	err := result.Status(http.StatusOK).LastError()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(result.Html())
}
