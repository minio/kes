// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package gcp

import (
	"testing"
)

func TestCredentials_MarshalJSON(t *testing.T) {
	for i, test := range marshalCredentialsTests {
		c := &Credentials{
			projectID: test.ProjectID,
			ClientID:  test.ClientID,
			Client:    test.ClientEmail,
			KeyID:     test.KeyID,
			Key:       test.Key,
		}
		got, err := c.MarshalJSON()
		if err != nil {
			t.Fatalf("Test %d: failed to marshal credentials: %v", i, err)
		}
		if s := string(got); s != test.JSON {
			t.Fatalf("Test %d:\n\ngot:\n%s\n\nwant:\n%s", i, s, test.JSON)
		}
	}
}

var marshalCredentialsTests = []struct {
	ProjectID   string
	ClientID    string
	ClientEmail string
	KeyID       string
	Key         string
	JSON        string
}{
	{
		ProjectID:   "decoded-agency-264617",
		ClientID:    "114153891410700359130",
		ClientEmail: "kes-testing-2022-11-23@decoded-agency-264617.iam.gserviceaccount.com",
		KeyID:       "765adce691b86b9dc5b0b74aeedf21e579dd18c9",
		Key:         "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCjB+YqqJJs1z7j\nniwNh8WvHelvkH0efrWWKZdYYyef43j8fnKZXV4pH8Pb0SHYayuwCoejSta62Tm5\n8sSdWGUe03XGX75bjJZHBnB3kWdVFq5vmRgXKhDDgXCLZeBDhXKKHL+gIApuHsw4\n1qjKMqnma5pb7lLoNKqjjz2u5amd5b0L8bS7O5jjfEvuQKv+iMuTnB/ONxhOGDaG\n4/lZ4ZsiN/BGURe1HnuoFNOz6nXo+37PZghCn5sn4rWe4QpsB/NdLLHJq4QW1qJq\nLqt/RoaAS8vo7J3OWpu4gsVC0B4fZ7oVVucYThQpa9zCQ504Sa9k+u6f0WBLztk/\nM34MxxEvAgMBAAECggEABEmY0620+XEAgt54ofvLYGPwqM/akOrPOf+M0Q50pECM\nwJjGt/fRPFL3vGTtIfCEZHqdFJNLNslJbdNYJ/lQBEkwC/Ad3Fey5nOuKvoHoKkr\nTzrUe/Xe6g7wACyi+l02aTKBBTl/SpdMn4C2PFdWwTBcuGbgU27gv0ptBQ83sGcf\nGQx7Kgcli5ZObkXOzpczw4YmqN9tp/D96qmwpRrt2KM8FWsU7dYeQs3IQwT9znGZ\n9/5RpbnS8jvNYZz0MY/fduzBvOrHgPn0UG5Y2a69MKMt9f7tpgYiAvUPk8xPsgBu\nCmFthVNipn9ndPu+ZDEkETe7GOUymNilJAezrcRn2QKBgQDWv+kSluqYeGV30Vks\nKzsfHJgCx/7MrFICd8mMSObfvwk4hIWhjtQ855BoAQQrBajCGFXBFEkb5LcRaney\nNVBbP7StfsPEdIeYEsqp0a5CtLicgeycEgZxUqCMa7NLbXEJzT77Zbgs/mNKOIRc\nYtJ4915toszcfdQ73Oj8a5tYAwKBgQDCWMVgSU3i7f9oSB8T/cg/x7OSYYOzbj8M\n404ZZNq5v6WD+xLpzIUl/QrpZXT6f0fc3ju7g7u0wU06LiSnBwdK5giRmt4PqOej\ngoPouGZMObYH8ivWQzBTEo5rh82XkAe72w0DZntURv+6BQ7t+3hh1dyBDcSSq8zo\nj0o5C+nIZQKBgFYbYTMo/CviqpzefmjtdKlG59TFqG8c8U04BsKPQLOaf/H/gS2E\nfalmGEr7jVZK0J3y7/+ZSK88iAMds5zrL6tG4gVm/Mw7BVt+vXBWOQ9aM2Pd3Ke/\nuoGZ5fIoBR5LZbXObGCVKsIvxlQuUTRSE56ZYW2Ih6gpc/4E2A7Oft1NAoGAQBYb\nx/uENn+6yD14GhSGsxl8SpnjXwjMu8g82bzbL4NV5ial/vjVM0i1D2/IWk4ceWXD\nFruC60EO4U+UAIwdyIIAc1s5PLq6371LGDOucBZbw1UFRZtUVSB6XFUk44S4OCcs\nrGFf69OZwlKmsK1K7iAinV/X4XHLmSifFh6qkc0CgYBNl278tyzngiJq+k9hoicv\nvYEEaV/umq1aoYiLC2t146nWyaX6L+uk2fn20wbhFRZ3NaECENFjCiFKsA8rirYb\nJkNqaKhqAVPeb32lT+4Y0rW9yS9/ym+wGTUEK4Ve6SBA2IHk4XP5tdeSd0+rdJdX\nMFcAgzLtDmU7p/t6oLZDMw==\n-----END PRIVATE KEY-----\n",
		JSON:        `{"type":"service_account","project_id":"decoded-agency-264617","private_key_id":"765adce691b86b9dc5b0b74aeedf21e579dd18c9","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCjB+YqqJJs1z7j\nniwNh8WvHelvkH0efrWWKZdYYyef43j8fnKZXV4pH8Pb0SHYayuwCoejSta62Tm5\n8sSdWGUe03XGX75bjJZHBnB3kWdVFq5vmRgXKhDDgXCLZeBDhXKKHL+gIApuHsw4\n1qjKMqnma5pb7lLoNKqjjz2u5amd5b0L8bS7O5jjfEvuQKv+iMuTnB/ONxhOGDaG\n4/lZ4ZsiN/BGURe1HnuoFNOz6nXo+37PZghCn5sn4rWe4QpsB/NdLLHJq4QW1qJq\nLqt/RoaAS8vo7J3OWpu4gsVC0B4fZ7oVVucYThQpa9zCQ504Sa9k+u6f0WBLztk/\nM34MxxEvAgMBAAECggEABEmY0620+XEAgt54ofvLYGPwqM/akOrPOf+M0Q50pECM\nwJjGt/fRPFL3vGTtIfCEZHqdFJNLNslJbdNYJ/lQBEkwC/Ad3Fey5nOuKvoHoKkr\nTzrUe/Xe6g7wACyi+l02aTKBBTl/SpdMn4C2PFdWwTBcuGbgU27gv0ptBQ83sGcf\nGQx7Kgcli5ZObkXOzpczw4YmqN9tp/D96qmwpRrt2KM8FWsU7dYeQs3IQwT9znGZ\n9/5RpbnS8jvNYZz0MY/fduzBvOrHgPn0UG5Y2a69MKMt9f7tpgYiAvUPk8xPsgBu\nCmFthVNipn9ndPu+ZDEkETe7GOUymNilJAezrcRn2QKBgQDWv+kSluqYeGV30Vks\nKzsfHJgCx/7MrFICd8mMSObfvwk4hIWhjtQ855BoAQQrBajCGFXBFEkb5LcRaney\nNVBbP7StfsPEdIeYEsqp0a5CtLicgeycEgZxUqCMa7NLbXEJzT77Zbgs/mNKOIRc\nYtJ4915toszcfdQ73Oj8a5tYAwKBgQDCWMVgSU3i7f9oSB8T/cg/x7OSYYOzbj8M\n404ZZNq5v6WD+xLpzIUl/QrpZXT6f0fc3ju7g7u0wU06LiSnBwdK5giRmt4PqOej\ngoPouGZMObYH8ivWQzBTEo5rh82XkAe72w0DZntURv+6BQ7t+3hh1dyBDcSSq8zo\nj0o5C+nIZQKBgFYbYTMo/CviqpzefmjtdKlG59TFqG8c8U04BsKPQLOaf/H/gS2E\nfalmGEr7jVZK0J3y7/+ZSK88iAMds5zrL6tG4gVm/Mw7BVt+vXBWOQ9aM2Pd3Ke/\nuoGZ5fIoBR5LZbXObGCVKsIvxlQuUTRSE56ZYW2Ih6gpc/4E2A7Oft1NAoGAQBYb\nx/uENn+6yD14GhSGsxl8SpnjXwjMu8g82bzbL4NV5ial/vjVM0i1D2/IWk4ceWXD\nFruC60EO4U+UAIwdyIIAc1s5PLq6371LGDOucBZbw1UFRZtUVSB6XFUk44S4OCcs\nrGFf69OZwlKmsK1K7iAinV/X4XHLmSifFh6qkc0CgYBNl278tyzngiJq+k9hoicv\nvYEEaV/umq1aoYiLC2t146nWyaX6L+uk2fn20wbhFRZ3NaECENFjCiFKsA8rirYb\nJkNqaKhqAVPeb32lT+4Y0rW9yS9/ym+wGTUEK4Ve6SBA2IHk4XP5tdeSd0+rdJdX\nMFcAgzLtDmU7p/t6oLZDMw==\n-----END PRIVATE KEY-----\n","client_email":"kes-testing-2022-11-23@decoded-agency-264617.iam.gserviceaccount.com","client_id":"114153891410700359130","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://accounts.google.com/o/oauth2/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"https://www.googleapis.com/robot/v1/metadata/x509/kes-testing-2022-11-23%40decoded-agency-264617.iam.gserviceaccount.com"}`,
	},
	{
		ProjectID:   "decoded-agency-264617",
		ClientID:    "114153891410700359130",
		ClientEmail: "kes-testing-2022-11-23@decoded-agency-264617.iam.gserviceaccount.com",
		KeyID:       "765adce691b86b9dc5b0b74aeedf21e579dd18c9",
		Key:         `-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCjB+YqqJJs1z7j\nniwNh8WvHelvkH0efrWWKZdYYyef43j8fnKZXV4pH8Pb0SHYayuwCoejSta62Tm5\n8sSdWGUe03XGX75bjJZHBnB3kWdVFq5vmRgXKhDDgXCLZeBDhXKKHL+gIApuHsw4\n1qjKMqnma5pb7lLoNKqjjz2u5amd5b0L8bS7O5jjfEvuQKv+iMuTnB/ONxhOGDaG\n4/lZ4ZsiN/BGURe1HnuoFNOz6nXo+37PZghCn5sn4rWe4QpsB/NdLLHJq4QW1qJq\nLqt/RoaAS8vo7J3OWpu4gsVC0B4fZ7oVVucYThQpa9zCQ504Sa9k+u6f0WBLztk/\nM34MxxEvAgMBAAECggEABEmY0620+XEAgt54ofvLYGPwqM/akOrPOf+M0Q50pECM\nwJjGt/fRPFL3vGTtIfCEZHqdFJNLNslJbdNYJ/lQBEkwC/Ad3Fey5nOuKvoHoKkr\nTzrUe/Xe6g7wACyi+l02aTKBBTl/SpdMn4C2PFdWwTBcuGbgU27gv0ptBQ83sGcf\nGQx7Kgcli5ZObkXOzpczw4YmqN9tp/D96qmwpRrt2KM8FWsU7dYeQs3IQwT9znGZ\n9/5RpbnS8jvNYZz0MY/fduzBvOrHgPn0UG5Y2a69MKMt9f7tpgYiAvUPk8xPsgBu\nCmFthVNipn9ndPu+ZDEkETe7GOUymNilJAezrcRn2QKBgQDWv+kSluqYeGV30Vks\nKzsfHJgCx/7MrFICd8mMSObfvwk4hIWhjtQ855BoAQQrBajCGFXBFEkb5LcRaney\nNVBbP7StfsPEdIeYEsqp0a5CtLicgeycEgZxUqCMa7NLbXEJzT77Zbgs/mNKOIRc\nYtJ4915toszcfdQ73Oj8a5tYAwKBgQDCWMVgSU3i7f9oSB8T/cg/x7OSYYOzbj8M\n404ZZNq5v6WD+xLpzIUl/QrpZXT6f0fc3ju7g7u0wU06LiSnBwdK5giRmt4PqOej\ngoPouGZMObYH8ivWQzBTEo5rh82XkAe72w0DZntURv+6BQ7t+3hh1dyBDcSSq8zo\nj0o5C+nIZQKBgFYbYTMo/CviqpzefmjtdKlG59TFqG8c8U04BsKPQLOaf/H/gS2E\nfalmGEr7jVZK0J3y7/+ZSK88iAMds5zrL6tG4gVm/Mw7BVt+vXBWOQ9aM2Pd3Ke/\nuoGZ5fIoBR5LZbXObGCVKsIvxlQuUTRSE56ZYW2Ih6gpc/4E2A7Oft1NAoGAQBYb\nx/uENn+6yD14GhSGsxl8SpnjXwjMu8g82bzbL4NV5ial/vjVM0i1D2/IWk4ceWXD\nFruC60EO4U+UAIwdyIIAc1s5PLq6371LGDOucBZbw1UFRZtUVSB6XFUk44S4OCcs\nrGFf69OZwlKmsK1K7iAinV/X4XHLmSifFh6qkc0CgYBNl278tyzngiJq+k9hoicv\nvYEEaV/umq1aoYiLC2t146nWyaX6L+uk2fn20wbhFRZ3NaECENFjCiFKsA8rirYb\nJkNqaKhqAVPeb32lT+4Y0rW9yS9/ym+wGTUEK4Ve6SBA2IHk4XP5tdeSd0+rdJdX\nMFcAgzLtDmU7p/t6oLZDMw==\n-----END PRIVATE KEY-----\n`,
		JSON:        `{"type":"service_account","project_id":"decoded-agency-264617","private_key_id":"765adce691b86b9dc5b0b74aeedf21e579dd18c9","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCjB+YqqJJs1z7j\nniwNh8WvHelvkH0efrWWKZdYYyef43j8fnKZXV4pH8Pb0SHYayuwCoejSta62Tm5\n8sSdWGUe03XGX75bjJZHBnB3kWdVFq5vmRgXKhDDgXCLZeBDhXKKHL+gIApuHsw4\n1qjKMqnma5pb7lLoNKqjjz2u5amd5b0L8bS7O5jjfEvuQKv+iMuTnB/ONxhOGDaG\n4/lZ4ZsiN/BGURe1HnuoFNOz6nXo+37PZghCn5sn4rWe4QpsB/NdLLHJq4QW1qJq\nLqt/RoaAS8vo7J3OWpu4gsVC0B4fZ7oVVucYThQpa9zCQ504Sa9k+u6f0WBLztk/\nM34MxxEvAgMBAAECggEABEmY0620+XEAgt54ofvLYGPwqM/akOrPOf+M0Q50pECM\nwJjGt/fRPFL3vGTtIfCEZHqdFJNLNslJbdNYJ/lQBEkwC/Ad3Fey5nOuKvoHoKkr\nTzrUe/Xe6g7wACyi+l02aTKBBTl/SpdMn4C2PFdWwTBcuGbgU27gv0ptBQ83sGcf\nGQx7Kgcli5ZObkXOzpczw4YmqN9tp/D96qmwpRrt2KM8FWsU7dYeQs3IQwT9znGZ\n9/5RpbnS8jvNYZz0MY/fduzBvOrHgPn0UG5Y2a69MKMt9f7tpgYiAvUPk8xPsgBu\nCmFthVNipn9ndPu+ZDEkETe7GOUymNilJAezrcRn2QKBgQDWv+kSluqYeGV30Vks\nKzsfHJgCx/7MrFICd8mMSObfvwk4hIWhjtQ855BoAQQrBajCGFXBFEkb5LcRaney\nNVBbP7StfsPEdIeYEsqp0a5CtLicgeycEgZxUqCMa7NLbXEJzT77Zbgs/mNKOIRc\nYtJ4915toszcfdQ73Oj8a5tYAwKBgQDCWMVgSU3i7f9oSB8T/cg/x7OSYYOzbj8M\n404ZZNq5v6WD+xLpzIUl/QrpZXT6f0fc3ju7g7u0wU06LiSnBwdK5giRmt4PqOej\ngoPouGZMObYH8ivWQzBTEo5rh82XkAe72w0DZntURv+6BQ7t+3hh1dyBDcSSq8zo\nj0o5C+nIZQKBgFYbYTMo/CviqpzefmjtdKlG59TFqG8c8U04BsKPQLOaf/H/gS2E\nfalmGEr7jVZK0J3y7/+ZSK88iAMds5zrL6tG4gVm/Mw7BVt+vXBWOQ9aM2Pd3Ke/\nuoGZ5fIoBR5LZbXObGCVKsIvxlQuUTRSE56ZYW2Ih6gpc/4E2A7Oft1NAoGAQBYb\nx/uENn+6yD14GhSGsxl8SpnjXwjMu8g82bzbL4NV5ial/vjVM0i1D2/IWk4ceWXD\nFruC60EO4U+UAIwdyIIAc1s5PLq6371LGDOucBZbw1UFRZtUVSB6XFUk44S4OCcs\nrGFf69OZwlKmsK1K7iAinV/X4XHLmSifFh6qkc0CgYBNl278tyzngiJq+k9hoicv\nvYEEaV/umq1aoYiLC2t146nWyaX6L+uk2fn20wbhFRZ3NaECENFjCiFKsA8rirYb\nJkNqaKhqAVPeb32lT+4Y0rW9yS9/ym+wGTUEK4Ve6SBA2IHk4XP5tdeSd0+rdJdX\nMFcAgzLtDmU7p/t6oLZDMw==\n-----END PRIVATE KEY-----\n","client_email":"kes-testing-2022-11-23@decoded-agency-264617.iam.gserviceaccount.com","client_id":"114153891410700359130","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://accounts.google.com/o/oauth2/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"https://www.googleapis.com/robot/v1/metadata/x509/kes-testing-2022-11-23%40decoded-agency-264617.iam.gserviceaccount.com"}`,
	},
}
