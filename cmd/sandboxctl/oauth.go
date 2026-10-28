package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"agent-sandbox/internal/model"
)

// oauth: subscription sign-ins sandboxd keeps fresh (POST /v1/oauth-credentials/{name}/login
// and friends). login starts the device flow, prints where to approve it and with which code,
// and waits until sandboxd reports the sign-in active or failed; no token ever reaches this
// side.
func (c *cli) oauth(fs *flag.FlagSet, pos, flags []string) error {
	sub := need(pos, 0, "login|list|show|remove")
	tenant := fs.String("tenant", "", "scope (admin): a tenant, or empty for the shared scope")
	provider := fs.String("provider", "", "login: the provider (a key of credentials.oauth.providers, e.g. chatgpt)")
	noWait := fs.Bool("no-wait", false, "login: print the URL and code and return; `oauth show` tells the outcome")
	wait := fs.Duration("wait", 16*time.Minute, "login: how long to wait for the approval")
	every := fs.Duration("every", 3*time.Second, "login: how often to ask for the outcome")
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(flags)
	q := ""
	if *tenant != "" {
		q = "?tenant=" + url.QueryEscape(*tenant)
	}
	switch sub {
	case "list":
		var list []model.OAuthCredential
		if err := c.do("GET", "/v1/oauth-credentials"+q, nil, &list); err != nil {
			return err
		}
		if *asJSON {
			printJSON(list)
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tPROVIDER\tSTATUS\tACCOUNT\tEXPIRES\tERROR")
		for _, o := range list {
			exp := ""
			if o.ExpiresAt != nil {
				exp = o.ExpiresAt.Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", o.Name, o.Provider, o.Status, o.AccountID, exp, o.Error)
		}
		tw.Flush()
	case "show":
		var o model.OAuthCredential
		if err := c.do("GET", "/v1/oauth-credentials/"+url.PathEscape(need(pos, 1, "name"))+q, nil, &o); err != nil {
			return err
		}
		printJSON(o)
	case "login":
		name := need(pos, 1, "name")
		if *provider == "" {
			return fmt.Errorf("oauth login: -provider is required")
		}
		path := "/v1/oauth-credentials/" + url.PathEscape(name)
		var o model.OAuthCredential
		if err := c.do("POST", path+"/login"+q, map[string]any{"provider": *provider}, &o); err != nil {
			return err
		}
		if *asJSON && *noWait {
			printJSON(o)
			return nil
		}
		fmt.Fprintf(os.Stderr, "Open %s and enter the code %s", o.VerificationURL, o.UserCode)
		if o.LoginExpiresAt != nil {
			fmt.Fprintf(os.Stderr, " before %s", o.LoginExpiresAt.Local().Format("15:04"))
		}
		fmt.Fprintln(os.Stderr, ".\nOnly continue if you started this sign-in: a code someone else gave you signs their agent in to your account.")
		if *noWait {
			return nil
		}
		for deadline := time.Now().Add(*wait); o.Status == model.OAuthPending; {
			if time.Now().After(deadline) {
				return fmt.Errorf("oauth login %s: still pending after %s (`sandboxctl oauth show %s` tells the outcome)", name, *wait, name)
			}
			time.Sleep(*every)
			if err := c.do("GET", path+q, nil, &o); err != nil {
				return err
			}
		}
		if *asJSON {
			printJSON(o)
		}
		if o.Status != model.OAuthActive {
			return fmt.Errorf("oauth login %s: %s: %s", name, o.Status, o.Error)
		}
		if !*asJSON {
			fmt.Printf("oauth %s: active (provider %s, account %s); secret:%s is its access token, secret:%s.account_id its account\n",
				o.Name, o.Provider, o.AccountID, o.Name, o.Name)
		}
	case "remove":
		name := need(pos, 1, "name")
		if err := c.do("DELETE", "/v1/oauth-credentials/"+url.PathEscape(name)+q, nil, nil); err != nil {
			return err
		}
		fmt.Println("removed", name)
	default:
		return fmt.Errorf("oauth: unknown subcommand %q", sub)
	}
	return nil
}
