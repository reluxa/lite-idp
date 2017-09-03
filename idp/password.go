// Copyright © 2017 Aaron Donovan <amdonov@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package idp

import (
	"errors"
	"net/http"

	"github.com/amdonov/lite-idp/model"
	"github.com/golang/protobuf/proto"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

type PasswordValidator interface {
	Validate(user, password string) error
}

type simpleValidator struct {
	users map[string][]byte
}

type UserPassword struct {
	Name     string
	Password string
}

func (sv *simpleValidator) Validate(user, password string) error {
	if pw, ok := sv.users[user]; ok {
		return bcrypt.CompareHashAndPassword(pw, []byte(password))
	}
	return errors.New("user not found")
}

func NewValidator() (PasswordValidator, error) {
	passwords := []UserPassword{}
	err := viper.UnmarshalKey("users", &passwords)
	if err != nil {
		return nil, err
	}
	users := make(map[string][]byte)
	for i := range passwords {
		users[passwords[i].Name] = []byte(passwords[i].Password)
	}
	return &simpleValidator{users}, nil
}

func (i *IDP) DefaultPasswordLoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := func() error {
			err := r.ParseForm()
			if err != nil {
				return err
			}
			requestId := r.Form.Get("requestId")
			data, err := i.TempCache.Get(requestId)
			if err != nil {
				return err
			}
			req := &model.AuthnRequest{}
			err = proto.Unmarshal(data, req)
			if err != nil {
				return err
			}
			userName := r.Form.Get("username")
			err = i.PasswordValidator.Validate(userName, r.Form.Get("password"))
			if err != nil {
				return err
			}
			// They have provided the right password
			user := &model.User{
				Name:    userName,
				Format:  "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
				Context: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				IP:      getIP(r).String()}

			// Add attributes
			err = i.setUserAttributes(user)
			if err != nil {
				return err
			}

			return i.respond(req, user, w, r)
		}()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
