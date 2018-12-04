package action

import (
	"io"

	"github.com/deis/duffle/pkg/claim"
	"github.com/deis/duffle/pkg/credentials"
	"github.com/deis/duffle/pkg/driver"
)

// Install describes an installation action
type Install struct {
	Driver driver.Driver // Needs to be more than a string
}

// Run performs an installation and updates the Claim accordingly
func (i *Install) Run(c *claim.Claim, creds credentials.Set, w io.Writer) error {
	invocImage, err := selectInvocationImage(i.Driver, c)
	if err != nil {
		return err
	}

	op, err := opFromClaim(claim.ActionInstall, c, invocImage, creds, w)
	if err != nil {
		return err
	}
	if err := i.Driver.Run(op); err != nil {
		c.Update(claim.ActionInstall, claim.StatusFailure)
		c.Result.Message = err.Error()
		return err
	}

	// Update claim:
	c.Update(claim.ActionInstall, claim.StatusSuccess)
	return nil
}
