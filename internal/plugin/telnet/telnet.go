package telnet

import (
	"github.com/chainreactors/zombie/pkg"
)

type TelnetPlugin struct {
	*pkg.Task
}

func (s *TelnetPlugin) Unauth() (bool, error) {
	c, err := NewClient(s.Address(), "", "", s.Duration())
	if err != nil {
		return false, err
	}
	err = c.Login()
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *TelnetPlugin) Login() error {
	c, err := NewClient(s.Address(), s.Username, s.Password, s.Duration())
	if err != nil {
		return err
	}
	err = c.Login()
	if err != nil {
		return err
	}

	return nil

}

func (s *TelnetPlugin) Close() error {
	return nil
}

func (s *TelnetPlugin) Name() string {
	return s.Service
}

func (s *TelnetPlugin) GetResult() *pkg.Result {
	// todo list dbs
	return &pkg.Result{Task: s.Task, OK: true}
}
