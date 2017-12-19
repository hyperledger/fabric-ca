/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// StreamJSONArray scans the JSON stream associated with 'decoder' to find
// an array value associated with the json element at 'pathToArray'.
// It then calls the 'cb' callback function so that it can decode one element
// in the stream at a time.

package streamer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

// StreamJSONArray scans the JSON stream associated with 'decoder' to find
// an array value associated with the json element at 'pathToArray'.
// It then calls the 'cb' callback function so that it can decode one element
// in the stream at a time.
func StreamJSONArray(decoder *json.Decoder, pathToArray string, cb func(decoder *json.Decoder) error) error {
	js := &jsonStream{decoder: decoder}
	err := js.findPath(strings.Split(pathToArray, "."))
	if err != nil {
		return err
	}
	err = js.assertDelim("[")
	if err != nil {
		return errors.Errorf("Expecting array value at '%s'", pathToArray)
	}
	// While the array contains values
	for decoder.More() {
		err = cb(decoder)
		if err != nil {
			return err
		}
	}
	return nil
}

type jsonStream struct {
	decoder *json.Decoder
}

func (js *jsonStream) findPath(path []string) error {
	if len(path) == 0 {
		// Found the path
		return nil
	}
	err := js.assertDelim("{")
	if err != nil {
		return err
	}
	for {
		str, err := js.getString()
		if err != nil {
			return err
		}
		if str == path[0] {
			break
		}
		err = js.skip()
		if err != nil {
			return err
		}
	}
	if len(path) == 1 {
		// Found the path
		return nil
	}
	return js.findPath(path[1:])
}

func (js *jsonStream) skip() error {
	t, err := js.getToken()
	if err != nil {
		return err
	}
	if _, ok := t.(json.Delim); !ok {
		// Was not a delimiter, so we're done
		return nil
	}
	// It was a delimiter, so skip to the matching delimiter
	d := fmt.Sprintf("%s", t)
	switch d {
	case "[":
		err = js.skipToDelim("]")
		if err != nil {
			return err
		}
	case "]":
		return errors.Errorf("Unexpected '%s'", d)
	case "{":
		err = js.skipToDelim("}")
		if err != nil {
			return err
		}
	case "}":
		err = errors.Errorf("Unexpected '%s'", d)
	default:
		err = errors.Errorf("unknown JSON delimiter: '%s'", d)
	}
	return err
}

func (js *jsonStream) skipToDelim(delim string) error {
	for {
		t, err := js.getToken()
		if err != nil {
			return err
		}
		// Skip anything that isn't a delimiter
		if _, ok := t.(json.Delim); !ok {
			continue
		}
		// It is a delimiter
		d := fmt.Sprintf("%s", t)
		if d == delim {
			return nil
		}
		switch d {
		case "[":
			err = js.skipToDelim("]")
		case "]":
			err = errors.Errorf("Expecting '%s' but found '%s'", delim, d)
		case "{":
			err = js.skipToDelim("}")
		case "}":
			err = errors.Errorf("Expecting '%s' but found '%s'", delim, d)
		default:
			err = errors.Errorf("unknown JSON delimiter: '%s'", d)
		}
		if err != nil {
			return err
		}
	}
}

func (js *jsonStream) assertDelim(delim string) error {
	t, err := js.getToken()
	if err != nil {
		return err
	}
	if _, ok := t.(json.Delim); !ok {
		return errors.Errorf("Invalid JSON; expecting delimiter but found '%s'", t)
	}
	d := fmt.Sprintf("%s", t)
	if d != delim {
		return errors.Errorf("Invalid JSON; expecting '%s' but found '%s'", delim, t)
	}
	return nil
}

func (js *jsonStream) getString() (string, error) {
	t, err := js.getToken()
	if err != nil {
		return "", err
	}
	var val string
	var ok bool
	if val, ok = t.(string); !ok {
		return "", errors.Errorf("Invalid JSON; expecting string but found '%s'", t)
	}
	return val, nil
}

func (js *jsonStream) getToken() (interface{}, error) {
	token, err := js.decoder.Token()
	// Commenting out following debug because is too verbose normally
	//log.Debugf("read token %s", token)
	return token, err
}
