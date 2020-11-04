# screnc.php
Microsoft Script Encoder / Decoder in PHP

## Usage
```php
require_once 'screnc.php';

$js = 'var a = "This is JScript Code"';

$encoded_js = WindowsScriptEncoder::encode($js);
$decoded_js = WindowsScriptEncoder::decode($encoded_js);
```
