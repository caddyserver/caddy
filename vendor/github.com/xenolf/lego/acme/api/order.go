package api

import (
	"encoding/base64"
	"errors"

	"github.com/xenolf/lego/acme"
)

type OrderService service

// New Creates a new order.
func (o *OrderService) New(domains []string) (acme.ExtendedOrder, error) {
	var identifiers []acme.Identifier
	for _, domain := range domains {
		identifiers = append(identifiers, acme.Identifier{Type: "dns", Value: domain})
	}

	orderReq := acme.Order{Identifiers: identifiers}

	var order acme.Order
	resp, err := o.core.post(o.core.GetDirectory().NewOrderURL, orderReq, &order)
	if err != nil {
		return acme.ExtendedOrder{}, err
	}

	return acme.ExtendedOrder{
		Location: resp.Header.Get("Location"),
		Order:    order,
	}, nil
}

// Get Gets an order.
func (o *OrderService) Get(orderURL string) (acme.Order, error) {
	if len(orderURL) == 0 {
		return acme.Order{}, errors.New("order[get]: empty URL")
	}

	var order acme.Order
	_, err := o.core.postAsGet(orderURL, &order)
	if err != nil {
		return acme.Order{}, err
	}

	return order, nil
}

// UpdateForCSR Updates an order for a CSR.
func (o *OrderService) UpdateForCSR(orderURL string, csr []byte) (acme.Order, error) {
	csrMsg := acme.CSRMessage{
		Csr: base64.RawURLEncoding.EncodeToString(csr),
	}

	var order acme.Order
	_, err := o.core.post(orderURL, csrMsg, &order)
	if err != nil {
		return acme.Order{}, err
	}

	if order.Status == acme.StatusInvalid {
		return acme.Order{}, order.Error
	}

	return order, nil
}
