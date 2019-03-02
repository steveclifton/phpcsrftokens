[![Latest Stable Version](https://poser.pugx.org/steveclifton/phpcsrftokens/v/stable)](https://packagist.org/packages/steveclifton/phpcsrftokens)
[![Total Downloads](https://poser.pugx.org/steveclifton/phpcsrftokens/downloads)](https://packagist.org/packages/steveclifton/phpcsrftokens)
[![License](https://poser.pugx.org/steveclifton/phpcsrftokens/license)](https://packagist.org/packages/steveclifton/phpcsrftokens)
[![Monthly Downloads](https://poser.pugx.org/steveclifton/phpcsrftokens/d/monthly)](https://packagist.org/packages/steveclifton/phpcsrftokens)
[![Daily Downloads](https://poser.pugx.org/steveclifton/phpcsrftokens/d/daily)](https://packagist.org/packages/steveclifton/phpcsrftokens)

# PHP Csrf Tokens

PHP Csrf Tokens is a simple session & cookie based csrf token generator and verifier.



## Installation

Via Composer


```bash
$ composer require steveclifton/phpcsrftokens
```

## Usage
For ease of use, all PHP Csrf Tokens methods have been made static to make generation and verification as simple as possible.

Following the OWASP guidelines, the `verifyToken()` method *does not* reset the tokens after each request, enabling double submission of the form.

Requires superglobal `$_SESSION` to be set.

```php
<?php

require_once __DIR__ /*Path To File*/;

use steveclifton\phpcsrftokens\Csrf;

session_start();

if (!empty($_GET['a'])) {
	echo '<pre>' . print_r($_POST, true) . '</pre>';
	echo 'Verification has been : ' . (Csrf::verifyToken('home') ? 'successful' : 'unsuccessful');
}

?>

<!DOCTYPE html>
<html>
<head><title>Test Script</title></head>
<body>
	<form action="?a=submit" method="POST">
		<?php echo Csrf::getInputToken('home') ?>
		<input type="text" name="name" placeholder="Test Input"><br>
		<button>Submit!</button>
	</form>
</body>
</html>
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.



## License

[MIT license](https://opensource.org/licenses/MIT).