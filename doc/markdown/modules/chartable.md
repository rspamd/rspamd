# Chartable module

This module allows to find number of characters from the different [unicode scripts](http://www.unicode.org/reports/tr24/). Finally, it evaluates number of scrips changes, e.g. 'a網絡a' is treated as 2 script changes - from latin to chineese and from chineese back to latin, divided by total number of unicode characters. If the product of this division is higher than threshold then a symbol is inserted. By default threshold is `0.1` meaning that script changes occurrs approximantely for 10% of characters.

~~~nginx
chartable {
  symbol = "R_CHARSET_MIXED";
  threshold = 0.1;
}
~~~