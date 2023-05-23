# airdom
# You can contribute to make it perfect:
# The main idea is to help prevent Domain Email Phishing, so this script will assist users to configure their email server to the best security it needs to have.
The script provided is designed to validate the domain email server. It allows users to enter a domain name through a form and sends a GET request to the server for validation. The script performs the following tasks:

1. Selects the necessary HTML elements such as the email form, domain input field, loader, result container, result display area, and error message display area.

2. Sets up an event listener on the email form to handle form submission.

3. When the form is submitted, the script performs the following actions:
   - Prevents the default form submission behavior.
   - Clears any previous results and error messages.
   - Retrieves the domain value entered by the user and trims any leading or trailing whitespace.

4. Validates the domain input using a regular expression to ensure it is in a valid format. The regular expression checks for common domain name conventions, including restrictions on hyphens, dots, and length limitations.

5. If the domain input is empty or fails the validation, an appropriate error message is displayed to the user.

6. If the domain input is valid, a GET request is sent to the server (`/validate-email`) with the encoded domain parameter.

7. The response from the server is parsed as JSON.

8. If the response is successful (HTTP status code 200), the script formats the received data and displays it in the result container. The displayed information includes DMARC, SPF, DKIM, MTA-STS, TLS, MX, and their respective recommendations.

9. If the response is unsuccessful, an error message from the server is displayed to the user.

10. If any error occurs during the process, a generic error message is displayed.

11. Finally, the loader is hidden.

By using this script, users can input a domain name and obtain information about the email server's DMARC, SPF, DKIM, MTA-STS, TLS, and MX configurations, along with recommendations for each. The script ensures that the domain input is properly validated and provides appropriate feedback to the user in case of errors or issues.

