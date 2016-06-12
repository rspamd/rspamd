# rspamd protocol

## Protocol basics

rspamd uses the HTTP protocol, either version 1.0 or 1.1. (There is also a compatibility layer described further in this document.) rspamd defines some headers which allow the passing of extra information about a scanned message, such as envelope data, IP address or SMTP sasl authentication data, etc. rspamd supports normal and chunked encoded HTTP requests.

## rspamd HTTP request

rspamd encourages the use of the HTTP protocol since it is standard and can be used by every programming language without the use of exotic libraries. A typical HTTP request looks like the following:

	POST /check HTTP/1.0
	Content-Length: 26969
	From: smtp@example.com
	Pass: all
	Ip: 95.211.146.161
	Helo: localhost.localdomain
	Hostname: localhost

	<your message goes here>

You can also use chunked encoding that allows streamlined data transfer which is useful if you don't know the length of a message.

### HTTP request

Normally, you should just use '/check' here. However, if you want to communicate with the controller then you might want to use controllers commands.

(TODO: write this part)

### HTTP headers

To avoid unnecessary work, rspamd allows an MTA to pass pre-processed data about the message by using either HTTP headers or a JSON control block (described further in this document). rspamd supports the following non-standard HTTP headers:

| Header          | Description                       |
| :-------------- | :-------------------------------- |
| **Deliver-To:** | Defines actual delivery recipient of message. Can be used for personalized statistics and for user specific options. |
| **IP:**         | Defines IP from which this message is received. |
| **Helo:**       | Defines SMTP helo |
| **Hostname:**   | Defines resolved hostname |
| **From:**       | Defines SMTP mail from command data |
| **Queue-Id:**   | Defines SMTP queue id for message (can be used instead of message id in logging). |
| **Rcpt:**       | Defines SMTP recipient (there may be several `Rcpt` headers) |
| **Pass:**       | If this header has `all` value, all filters would be checked for this message. |
| **Subject:**    | Defines subject of message (is used for non-mime messages). |
| **User:**       | Defines SMTP user. |
| **Message-Length:** | Defines the length of message excluding the control block. |

Controller also defines certain headers:

(TODO: write this part)

Standard HTTP headers, such as `Content-Length`, are also supported.

## rspamd HTTP reply

rspamd reply is encoded in `JSON`. Here is a typical HTTP reply:

	HTTP/1.1 200 OK
	Connection: close
	Server: rspamd/0.9.0
	Date: Mon, 30 Mar 2015 16:19:35 GMT
	Content-Length: 825
	Content-Type: application/json

~~~json
{
    "default": {
        "is_spam": false,
        "is_skipped": false,
        "score": 5.2,
        "required_score": 7,
        "action": "add header",
        "DATE_IN_PAST": {
            "name": "DATE_IN_PAST",
            "score": 0.1
        },
        "FORGED_SENDER": {
            "name": "FORGED_SENDER",
            "score": 5
        },
        "TEST": {
            "name": "TEST",
            "score": 100500
        },
        "FUZZY_DENIED": {
            "name": "FUZZY_DENIED",
            "score": 0,
            "options": [
                "1: 1.00 / 1.00",
                "1: 1.00 / 1.00"
            ]
        },
        "HFILTER_HELO_5": {
            "name": "HFILTER_HELO_5",
            "score": 0.1
        }
    },
    "urls": [
        "www.example.com",
        "another.example.com"
    ],
    "emails": [
        "user@example.com"
    ],
    "message-id": "4E699308EFABE14EB3F18A1BB025456988527794@example"
}
~~~

For convenience, the reply is LINTed using [jsonlint](http://jsonlint.com). The actual reply is compressed for speed.

The reply can be treated as a JSON object where keys are metric names (namely `default`) and values are objects that represent metrics.

Each metric has the following fields:

* `is_spam` - boolean value that indicates whether a message is spam
* `is_skipped` - boolean flag that is `true` if a message has been skipped due to settings
* `score` - floating point value representing the effective score of message
* `required_score` - floating point value meaning the treshold value for the metric
* `action` - recommended action for a message:
	- `no action` - message is likely ham;
	- `greylist` - message should be greylisted;
	- `add header` - message is suspicious and should be marked as spam
	- `rewrite subject` - message is suspicious and should have subject rewritten
	- `soft reject` - message should be temporary rejected (for example, due to rate limit exhausting)
	- `reject` - message should be rejected as spam

Additionally, metric contains all symbols added during a message's processing, indexed by symbol names.

Additional keys which may be in the reply include:

* `subject` - if action is `rewrite subject` this value defines the desired subject for a message
* `urls` - a list of urls found in a message (only hostnames)
* `emails` - a list of emails found in a message
* `message-id` - ID of message (useful for logging)
* `messages` - array of optional messages added by rspamd filters (such as `SPF`)

## rspamd JSON control block

Since rspamd version 0.9 it is also possible to pass additional data by prepending a JSON control block to a message. So you can use either headers or a JSON block to pass data from the MTA to rspamd.

To use a JSON control block, you need to pass an extra header called `Message-Length` to rspamd. This header should be equal to the size of the message **excluding** the JSON control block. Therefore, the size of the control block is equal to `Content-Length - Message-Length`. rspamd assumes that a message starts immediately after the control block (with no extra CRLF). This method is equally compatible with streaming transfer, however even if you are not specifying `Content-Length` you are still required to specify `Message-Length`.

Here is an example of a JSON control block:

~~~json
{
	"from": "smtp@example.com",
	"pass_all": "true",
	"ip": "95.211.146.161",
	"helo": "localhost.localdomain",
	"hostname": "localhost"
}
~~~

Moreover, [UCL](https://github.com/vstakhov/libucl) json extensions and syntax conventions are also supported inside the control block.

## Legacy RSPAMC protocol

For compatibility, rspamd supports legacy `RSPAMC` and also SpamAssassin `SPAMC` protocols. Though their usage is discouraged, these protocols can still be used as a last resort to communicate with rspamd from legacy applications.

The RSPAMC dialog looks as follows:

~~~
SYMBOLS RSPAMC/1.1
Content-Length: 2200

<message octets>

RSPAMD/1.1 0 OK
Metric: default; True; 10.40 / 10.00 / 0.00
Symbol: R_UNDISC_RCPT
Symbol: ONCE_RECEIVED
Symbol: R_MISSING_CHARSET
Urls:
~~~

The RSPAMC protocol also supports different commands:

| Command | Description |
| :-------| :----- |
| CHECK   | Check a message and output results for each metric, but do not output symbols. |
| SYMBOLS | Same as `CHECK`, but output symbols. |
| PROCESS | Same as `SYMBOLS` but also output the original message with inserted X-Spam headers. |
| PING    | Do not do any processing, just check rspamd state. |


After the command, there should be one mandatory header - `Content-Length` - which defines a message's length in bytes, and optional headers (same as for HTTP).

rspamd supports SpamAssassin's `spamc` protocol, and you can even pass rspamc headers in spamc mode, but the reply of rspamd in `spamc` mode is truncated to the "default" metric only with no options for symbols being displayed. Rspamc reply looks as follows: 

	RSPAMD/1.1 0 OK
	Metric: default; True; 10.40 / 10.00 / 0.00
	Symbol: R_UNDISC_RCPT
	Symbol: ONCE_RECEIVED
	Symbol: R_MISSING_CHARSET
	Urls: 
 
