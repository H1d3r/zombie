package rsync

import (
	"github.com/chainreactors/zombie/pkg"
)

type RsyncPlugin struct {
	*pkg.Task
}

func (s *RsyncPlugin) Unauth() (bool, error) {
	ver, modules, err := RsyncDetect(s.Address(), s.Timeout)
	if err != nil {
		return false, err
	}
	err = RsyncUnauth(s.Address(), ver, modules, s.Timeout)
	if err != nil {
		return false, err
	}
	return true, nil
}

//func (s *RsyncPlugin) Query() bool {
//	return false
//}
//
//func (s *RsyncPlugin) GetInfo() bool {
//	return false
//}

func (s *RsyncPlugin) Login() error {
	ver, modules, err := RsyncDetect(s.Address(), s.Timeout)
	if err != nil {
		return err
	}

	err = RsyncLogin(s.Address(), s.Username, s.Password, ver, modules, s.Timeout)
	if err != nil {
		return err
	}

	return nil
}

func (s *RsyncPlugin) Name() string {
	return s.Service
}

func (s *RsyncPlugin) GetResult() *pkg.Result {
	// todo list dbs
	return &pkg.Result{Task: s.Task, OK: true}
}

func (s *RsyncPlugin) Close() error {
	return nil
}
