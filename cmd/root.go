/*
Johann Van Niekerk hdysec@gmail.com
*/

package cmd

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Initialise colors for CLI output
var cRed = color.New(color.FgHiWhite, color.BgHiRed)
var cRedB = color.New(color.FgBlack, color.BgHiRed)
var cGreen = color.New(color.FgBlack, color.BgHiGreen)
var cYellow = color.New(color.FgBlack, color.BgHiYellow)
var greenPlus = fmt.Sprintf("[%s]", color.HiGreenString("++"))
var redMinus = fmt.Sprintf("[%s]", color.HiRedString("--"))
var yellowPlus = fmt.Sprintf("[%s]", color.HiYellowString("+-"))

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "hdySecurityHeaders",
	Short: "Simple Security Header Scanner",
	Long: `A simple tool to scan for existing security headers and review which are missing. Tool allows for manual review of directives to ensure they are relevant to the environment. 

Usage:
hdySecurityHeaders -d <domain.com>
hdySecurityHeaders -d <domain.com> -P "http://127.0.0.1:8081"
hdySecurityHeaders -d "subdomain.example.com:8080/service/dashboard.mvc" -H "Cookie: JSESSIONID=qwerqwer_aadsfasdfasdasdfd-Afdfdfp"
`,

	Run: func(cmd *cobra.Command, args []string) {
		//fmt.Println("Debug: Into main()")
		printBanner()

		// Check if the domain flag was provided otherwise display help menu
		userInput, err := cmd.Flags().GetString("domain")
		if err != nil { // Check for any error returned by GetString
			fmt.Printf("Error reading 'domain' flag: %v\n", err)
			os.Exit(1) // Exit with an error status code
		}
		if userInput == "" {
			fmt.Println("The 'domain' flag is required.")
			cmd.Help() // Display help menu
			os.Exit(1) // Exit with an error status code
		}

		// Send: userInput to cleanUrl()
		// Recv: variables containing both http and https urls
		httpUrl, httpsUrl := cleanUrl(userInput)
		cleanedUrls := []string{httpUrl, httpsUrl}

		getRequest(cmd, cleanedUrls)
		fmt.Printf("%s Finished", greenPlus)
	},
}

func printBanner() {
	banner := []string{
		"#-+-+-+-+-+-+-+-+-+-#",
		"#hdySecurityHeaders #",
		"#-+-+-+-+-+-+-+-+-+-#",
	}

	for _, line := range banner {
		fmt.Println(line)
	}
}

func matchProvisionalHeaders() map[string]string {
	return map[string]string{
		"X-Permitted-Cross-Domain-Policies": "RECOMMEND: 'X-Permitted-Cross-Domain-Policies: none'; Cross-domain policies",
		"X-Frame-Options":                   "RECOMMEND: Both CSP has 'frame-ancestors' directive and recommend X-Frame-Options to cover older browsers who don't support CSP - 'X-Frame-Options: DENY' or SAMEORIGIN for only framing by origin domain (if required); Prevents Clickjacking",
		"Cross-Origin-Embedder-Policy":      "RECOMMEND: 'Cross-Origin-Embedder-Policy: require-corp';  Controls cross-origin requests",
		"Cross-Origin-Resource-Policy":      "RECOMMEND: 'Cross-Origin-Resource-Policy: same-site'; Resource sharing policy",
		"Cross-Origin-Opener-Policy":        "RECOMMEND: 'Cross-Origin-Opener-Policy: same-origin'; Controls window.open()",
		"Access-Control-Allow-Origin":       "RECOMMEND: 'Access-Control-Allow-Origin: https://yoursite.com'; avoid use of Wildcards",
		"Cache-Control":                     "RECOMMEND: 'Cache-Control: no-cache, no-store'; no-cache by itself is not enough and requires no-store; Header only applicable for sensitive pages (credit card # etc) and not simply landing pages. ",
	}
}

func matchRecommendedHeaders() map[string]string {
	return map[string]string{
		"Content-Security-Policy":   "RECOMMEND: 'Content-Security-Policy: default-src 'self' *.domain.com'; Check 'script-src' contains self or domain &  for 'unsafe-inline' - Do not use || Not to be raised with an API only endpoint",
		"X-Content-Type-Options":    "RECOMMEND: 'X-Content-Type-Options: nosniff' Prevents MIME-sniffing",
		"Strict-Transport-Security": "RECOMMEND: 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' & HSTS to appear on all pages",
		"Referrer-Policy":           "RECOMMEND: 'Referrer-Policy: strict-origin-when-cross-origin'",
		"Permissions-Policy":        "RECOMMEND: 'Permissions-Policy: geolocation=(), camera=(), microphone=()'; Delegates API permissions",
		"Cache-Control":             "RECOMMEND: 'Cache-Control: no-cache, no-store' or 'Cache-Control: no-store / Pragma: no-cache / Expires: -1' ; no-cache by itself is not enough and requires no-store; Header only applicable for sensitive pages (credit card # etc) and not simply landing pages. ",
		"Pragma":                    "RECOMMEND: 'Pragma: no-cache'",
	}
}

func matchRemoveableHeaders() map[string]string {
	return map[string]string{
		"X-Xss-Protection":          "DEPRECATED: if support for legacy browsers isn’t required, this header should be disabled using 'X-Xss-Protection: 0' in lieu of CSP instead; refer to documentation for recommendation; Should look into CSP instead",
		"Public-Key-Pins":           "DEPRECATED: Do not use; Certificate pinning",
		"X-Content-Security-Policy": "DEPRECATED: Do not use",
		"X-Webkit-CSP":              "DEPRECATED: Do not use",
		"Expect-CT":                 "DEPRECATED: Do not use",
		"Server":                    "REMOVE: Remove this header or set non-informative values",
		"X-Powered-By":              "REMOVE: Remove all 'X-Powered-By' headers to prevent fingerprinting tech stack",
		"X-AspNet-Version":          "REMOVE: Remove this header to prevent fingerprinting tech stack",
		"X-AspNetMvc-Version":       "REMOVE: Remove this header to prevent fingerprinting tech stack",
	}
}

func cleanUrl(httpUrl string) (string, string) {
	//fmt.Println("Debug: Into cleanHttpUrl()")

	// Strip the protocol for HTTP and HTTPS if provided - necessary to perform scan on both HTTP and HTTPS of URL
	providedUrl := strings.TrimPrefix(httpUrl, "http://")
	providedUrl = strings.TrimPrefix(providedUrl, "https://")

	httpVersion := "http://" + providedUrl
	httpsVersion := "https://" + providedUrl

	return httpVersion, httpsVersion
}

func getRequest(cmd *cobra.Command, httpUrl []string) {
	// Issue GET Requests
	//fmt.Println("Debug: Into getRequest()")

	// Setup to use proxy string if there is a string provided otherwise use default http.client{}
	var client *http.Client
	proxyValue, _ := cmd.Flags().GetString("proxy")

	// Configure HTTP Client to use burp proxy if proxy flag provided
	if proxyValue != "" {
		proxyUrl, err := url.Parse(proxyValue)
		if err != nil {
			fmt.Printf("%s Error parsing proxy URL, \n%s\n", redMinus, err)
			return
		}
		client = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyUrl),
			},
		}
	} else {
		client = &http.Client{}
	}

	// Perform requests on each URL provided
	for _, url := range httpUrl {
		fmt.Printf("%s Domain Protocol: %s\n", greenPlus, url)

		// Create GET Request
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Printf("%s Error creating HTTP GET Request, \n%s\n", redMinus, err)
			return
		}

		// handle redirect if flag is provided.
		runRedirect, _ := cmd.Flags().GetBool("redirect") // check if redirect flag is set
		if !runRedirect {
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		}

		// set custom user-agent and static headers
		request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0")
		request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		request.Header.Set("Accept-Language", "en-US;q=0.8,en;q=0.3")
		request.Header.Set("Upgrade-Insecure-Requests", "1")

		// functionality to set custom header
		headerValue, _ := cmd.Flags().GetString("header")
		if headerValue != "" {
			headerParts := strings.SplitN(headerValue, ": ", 2)
			headerKey := strings.TrimSpace(headerParts[0])
			headerV := strings.TrimSpace(headerParts[1])
			request.Header.Set(headerKey, headerV)
		}

		// retrieve server response
		response, err := client.Do(request)
		if err != nil {
			fmt.Printf("Error sending GET requests to the slice of URLs, \n%s\n", err)
			continue // continue to next url if there is an error with the first regardless
		}
		if response.StatusCode == 200 {
			//color.Green("HTTP Code: %d\n", response.StatusCode)
			fmt.Printf("%s HTTP Code: %s", greenPlus, color.HiGreenString("%d \n", response.StatusCode))

		} else {
			fmt.Printf("%s HTTP Code: %s", redMinus, color.HiRedString("%d 	Enable '-r' to follow redirects or '-H <header>' for custom headers\n", response.StatusCode))
		}

		formatHeaders(response.Header)
		defer response.Body.Close() // make sure app closes the response after finishing getRequest() function
	}
}

func formatHeaders(responseHeaders http.Header) {

	var (
		// set variables to retrieve map of keys:values to filter against
		recommendedHeaders = matchRecommendedHeaders()
		provisionalHeaders = matchProvisionalHeaders()
		removeableHeaders  = matchRemoveableHeaders()

		// provision slices for loop data
		goodHeaders      []string
		provHeaders      []string
		badHeaders       []string
		missingHeaders   []string
		remainingHeaders []string

		//track headers seen to identify remaining ones later (what's left over and not filtered out into their category)
		seenHeaders = map[string]bool{}
	)

	// Filter all headers from response based on the MAPS then assign to variables to print based on assignment
	for k, values := range responseHeaders {
		seenHeaders[k] = true // Mark this header as seen
		valueStr := fmt.Sprintf("%s: %s", k, strings.Join(values, ", "))
		if _, ok := recommendedHeaders[k]; ok {
			goodHeaders = append(goodHeaders, valueStr)
		} else if _, ok := provisionalHeaders[k]; ok {
			provHeaders = append(provHeaders, valueStr)
		} else if _, ok := removeableHeaders[k]; ok {
			badHeaders = append(badHeaders, valueStr)
		} else {
			remainingHeaders = append(remainingHeaders, valueStr)
		}
	}

	for k := range recommendedHeaders {
		if !seenHeaders[k] {
			missingHeaders = append(missingHeaders, "MISSING: "+k)
		}
	}

	fmt.Printf("%s Security Headers Enabled:\n", greenPlus)
	for _, h := range goodHeaders {
		parts := strings.SplitN(h, ": ", 2)
		if len(parts) == 2 {
			headerStr := cGreen.Sprintf("	FOUND: %s: %s", parts[0], parts[1]) // Create a colored string
			fmt.Println(headerStr)                                            // Print the header in green
			// Print the recommendation from the map
			if recommendation, ok := recommendedHeaders[parts[0]]; ok {
				fmt.Printf("	  -> %s\n", recommendation) // This will now be in default color
			}
		} else {
			cGreen.Println("FOUND: " + h) // In case the header doesn't contain ": " then print the whole string
		}
	}
	fmt.Printf("%s Provisional Security Headers Enabled:\n", yellowPlus)

	//fmt.Println("\nProvisional Headers (requires focus):")
	for _, h := range provHeaders {
		parts := strings.SplitN(h, ": ", 2)
		if len(parts) == 2 {
			headerStr := cYellow.Sprintf("	FOUND: %s: %s", parts[0], parts[1]) // Create a colored string
			fmt.Println(headerStr)                                             // Print the header in green
			// Print the recommendation from the map
			if recommendation, ok := provisionalHeaders[parts[0]]; ok {
				fmt.Printf("	  -> %s\n", recommendation) // This will now be in default color
			}
		} else {
			cYellow.Println("FOUND: " + h) // In case the header doesn't contain ": " then print the whole string
		}
	}
	fmt.Printf("%s Missing Security Headers:\n", redMinus)

	for _, h := range missingHeaders {
		parts := strings.SplitN(h, ": ", 2)
		if len(parts) == 2 {
			headerStr := cRed.Sprintf("	%s: %s", parts[0], parts[1]) // Create a colored string
			fmt.Println(headerStr)                                   // Print the header in green
			// Print the recommendation from the map
			if recommendation, ok := recommendedHeaders[parts[0]]; ok {
				fmt.Printf("	  -> %s\n", recommendation) // This will now be in default color
			}
		} else {
			cRed.Println("FOUND: " + h) // In case the header doesn't contain ": " then print the whole string
		}
	}
	fmt.Printf("%s Deprecated or Bad Headers Enabled:\n", redMinus)

	for _, h := range badHeaders {
		parts := strings.SplitN(h, ": ", 2)
		if len(parts) == 2 {
			headerStr := cRedB.Sprintf("	REMOVE: %s: %s", parts[0], parts[1]) // Create a colored string
			fmt.Println(headerStr)                                            // Print the header in green
			// Print the recommendation from the map
			if recommendation, ok := removeableHeaders[parts[0]]; ok {
				fmt.Printf("	  -> %s\n", recommendation) // This will now be in default color
			}
		} else {
			cRedB.Println("FOUND: " + h) // In case the header doesn't contain ": " then print the whole string
		}
	}

	fmt.Printf("%s Remaining Headers Enabled:\n", greenPlus)
	for _, h := range remainingHeaders {
		parts := strings.SplitN(h, ": ", 2)
		if len(parts) == 2 { // Check if the header string is properly split into <key> and <value>
			colorKey := color.New(color.FgHiMagenta)
			colorKey.Printf("	%s: ", parts[0]) // Print the <key> in color
			fmt.Println(parts[1])              // Print the <value> normally
		} else {
			fmt.Println(h) // In case the header doesn't contain ": " then print the whole string
		}
	}
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringP("domain", "d", "", "Provide the domain excluding the protocol (http/s://). The tool works with the absolute path and won't follow redirects")
	rootCmd.MarkFlagRequired("domain")
	rootCmd.PersistentFlags().StringP("header", "H", "", "Provide optional header to include in scanning when doing authenticated scanning.")
	rootCmd.PersistentFlags().StringP("proxy", "P", "", "Provide optional proxy for Burp or Zap interception (http://127.0.0.1:8081)")
	rootCmd.Flags().BoolP("redirect", "r", false, "Instruct tool to follow redirect (Default is to ignore redirects)")
}
