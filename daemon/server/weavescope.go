package server

import (
	"bufio"
	"bytes"
	"net/http"

	"github.com/ugorji/go/codec"
)

func (router *RouterBackend) weaveScopeReport(w http.ResponseWriter, r *http.Request) {
	report, err := router.daemon.WeaveScopeReport()
	if err != nil {
		processServerError(w, r, err)
		return
	}

	log.Debugf("weaveScopeReport reply: %+v", report)
	var b bytes.Buffer
	foo := bufio.NewWriter(&b)
	err = codec.NewEncoder(foo, &codec.MsgpackHandle{}).Encode(report)
	foo.Flush()
	log.Debugf("weaveScopeReport Bytes: %s, %s", err, b.String())

	w.WriteHeader(http.StatusOK)
	if err := codec.NewEncoder(w, &codec.MsgpackHandle{}).Encode(report); err != nil {
		processServerError(w, r, err)
		return
	}
}
