package iptables

import (
	"fmt"
	"net"

	"github.com/riete/exec"
)

const (
	Accept = "ACCEPT"
	Drop   = "DROP"
)

type RuleBuilder interface {
	SetSource()
	SetDestination()
	SetComment()
	SetAction()
	GetSpec() []string
}

type SrcIpNetDestTcpPortRule struct {
	src     *net.IPNet
	port    string
	comment string
	action  string
	spec    []string
}

func (s *SrcIpNetDestTcpPortRule) SetSource() {
	if s.src != nil {
		s.spec = append(s.spec, "-s", s.src.String())
	}
}

func (s *SrcIpNetDestTcpPortRule) SetDestination() {
	if s.port != "" {
		s.spec = append(s.spec, "-p", "tcp", "--dport", s.port)
	}
}

func (s *SrcIpNetDestTcpPortRule) SetAction() {
	s.spec = append(s.spec, "-j", s.action)
}

func (s *SrcIpNetDestTcpPortRule) SetComment() {
	if s.comment != "" {
		s.spec = append(s.spec, "-m", "comment", "--comment", s.comment)
	}
}

func (s *SrcIpNetDestTcpPortRule) GetSpec() []string {
	return s.spec
}

func NewSrcIpNetDestTcpPortRuleBuilder(src *net.IPNet, port, comment, action string) RuleBuilder {
	s := &SrcIpNetDestTcpPortRule{src: src, port: port, comment: comment, action: action}
	s.SetSource()
	s.SetDestination()
	s.SetComment()
	s.SetAction()
	return s
}

type IptablesCommandArgsBuilder struct{}

func (IptablesCommandArgsBuilder) CheckChainExist(chain string) []string {
	return []string{"-L", chain, "-n"}
}

func (IptablesCommandArgsBuilder) CheckRuleExist(chain string, rule RuleBuilder) []string {
	return append([]string{"-C", chain}, rule.GetSpec()...)
}

func (IptablesCommandArgsBuilder) NewChain(chain string) []string {
	return []string{"-N", chain}
}

func (IptablesCommandArgsBuilder) AppendRule(chain string, rule RuleBuilder) []string {
	return append([]string{"-A", chain}, rule.GetSpec()...)
}

func (IptablesCommandArgsBuilder) InsertRule(chain string, num int64, rule RuleBuilder) []string {
	return append([]string{"-I", chain, fmt.Sprintf("%d", num)}, rule.GetSpec()...)
}

func (IptablesCommandArgsBuilder) ReplaceRule(chain string, num int64, rule RuleBuilder) []string {
	return append([]string{"-R", chain, fmt.Sprintf("%d", num)}, rule.GetSpec()...)
}

func (IptablesCommandArgsBuilder) DeleteRule(chain string, rule RuleBuilder) []string {
	return append([]string{"-D", chain}, rule.GetSpec()...)
}

func (IptablesCommandArgsBuilder) DeleteRuleByNum(chain string, num int64) []string {
	return []string{"-D", chain, fmt.Sprintf("%d", num)}
}

func NewIptablesCommandArgsBuilder() *IptablesCommandArgsBuilder {
	return &IptablesCommandArgsBuilder{}
}

type IptablesManager struct {
	c *IptablesCommandArgsBuilder
	r *exec.Cmd
}

func (i *IptablesManager) run(args ...string) (string, error) {
	i.r.SetCmd("iptables", args...)
	return i.r.RunWithCombinedOutput()
}

func (i *IptablesManager) ChainExist(chain string) bool {
	_, err := i.run(i.c.CheckChainExist(chain)...)
	return err == nil
}

func (i *IptablesManager) RuleExist(chain string, rule RuleBuilder) bool {
	_, err := i.run(i.c.CheckRuleExist(chain, rule)...)
	return err == nil
}

func (i *IptablesManager) NewChain(chain string) (string, error) {
	return i.run(i.c.NewChain(chain)...)
}

func (i *IptablesManager) AppendRule(chain string, rule RuleBuilder) (string, error) {
	return i.run(i.c.AppendRule(chain, rule)...)
}

func (i *IptablesManager) InsertRule(chain string, num int64, rule RuleBuilder) (string, error) {
	return i.run(i.c.InsertRule(chain, num, rule)...)
}

func (i *IptablesManager) ReplaceRule(chain string, num int64, rule RuleBuilder) (string, error) {
	return i.run(i.c.ReplaceRule(chain, num, rule)...)
}

func (i *IptablesManager) DeleteRule(chain string, rule RuleBuilder) (string, error) {
	return i.run(i.c.DeleteRule(chain, rule)...)
}

func (i *IptablesManager) DeleteRuleByNum(chain string, num int64) (string, error) {
	return i.run(i.c.DeleteRuleByNum(chain, num)...)
}

func NewIptablesManager() *IptablesManager {
	return &IptablesManager{r: exec.NewCmdRunner(), c: NewIptablesCommandArgsBuilder()}
}
