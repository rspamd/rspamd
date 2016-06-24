# rspamd composite symbols

## Introduction

rspamd composites are used to combine rules and create more complex rules. Composite rules are defined by `composite` keys. The value of the key should be an object that defines the composite's name and value, which is the combination of rules in a joint expression.

For example, you can define a composite that is added when two specific symbols are found:

~~~ucl
composite {
	name = "TEST_COMPOSITE";
	expression = "SYMBOL1 and SYMBOL2";
}
~~~

In this case, if a message has both `SYMBOL1` and `SYMBOL2` then they are replaced by symbol `TEST_COMPOSITE`. The weights of `SYMBOL1` and `SYMBOL2` are subtracted from the metric accordingly.

## Composite expressions

You can use the following operations in a composite expression:

* `AND` `&` - matches true only if both operands are true
* `OR` `|` - matches true if any operands are true
* `NOT` `!` - matches true if operand is false

You also can use braces to define priorities. Otherwise operators are evaluated from left to right. For example:

~~~ucl
composite {
    name = "TEST";
    expression = "SYMBOL1 and SYMBOL2 and ( not SYMBOL3 | not SYMBOL4 | not SYMBOL5 )";
}
~~~

Composite rule can include other composites in the body. There is no restriction on definition order:

~~~ucl
composite {
    name = "TEST1";
    expression = "SYMBOL1 AND TEST2";
}
composite {
    name = "TEST2";
    expression = "SYMBOL2 OR NOT SYMBOL3";
}
~~~

Composites should not be recursive; this is normally detected by rspamd.

## Composite weight rules

Composites can record symbols in a metric or record their weights. That could be used to create non-captive composites. For example, you have symbol `A` and `B` with weights `W_a` and `W_b` and a composite `C` with weight `W_c`.

* If `C` is `A & B` then if rule `A` and rule `B` matched then these symbols are *removed* and their weights are removed as well, leading to a single symbol `C` with weight `W_c`.
* If `C` is `-A & B`, then rule `A` is preserved, but the symbol `C` is inserted. The weight of `A` is preserved as well, so the total weight of `-A & B` will be `W_a + W_c`.
* If `C` is `~A & B`, then rule `A` is *removed* but its weight is *preserved*,
  leading to a single symbol `C` with weight `W_a + W_c`

When you have multiple composites which include the same symbol and a composite wants to remove the symbol and another composite wants to preserve it, then the symbol is preserved by default. Here are some more examples:

~~~ucl
composite "COMP1" {
    expression = "BLAH || !DATE_IN_PAST";
}
composite "COMP2" {
    expression = "!BLAH || DATE_IN_PAST";
}
composite "COMP3" {
    expression = "!BLAH || -DATE_IN_PAST";
}
~~~

Both `BLAH` and `DATE_IN_PAST` exist in the message's check results. However, `COMP3` wants to preserve `DATE_IN_PAST` so it will be saved in the output.

If we rewrite the previous example but replace `-` with `~` then `DATE_IN_PAST` will be removed (however, its weight won't be removed):

~~~ucl
composite "COMP1" {
    expression = "BLAH || !DATE_IN_PAST";
}
composite "COMP2" {
    expression = "!BLAH || DATE_IN_PAST";
}
composite "COMP3" {
    expression = "!BLAH || ~DATE_IN_PAST";
}
~~~

When we want to remove a symbol, despite other composites combinations, it is possible to add the prefix `^` to the symbol:

~~~ucl
composite "COMP1" {
    expression = "BLAH || !DATE_IN_PAST";
}
composite "COMP2" {
    expression = "!BLAH || ^DATE_IN_PAST";
}
composite "COMP3" {
    expression = "!BLAH || -DATE_IN_PAST";
}
~~~

In this example `COMP3` wants to save `DATE_IN_PAST` once again, however `COMP2` overrides this and removes `DATE_IN_PAST`.

## Composites with symbol groups

It is possible to include a group of symbols in a composite rule. This effectively means **any** symbol of the specified group:

~~~ucl
composite {
    name = "TEST2";
    expression = "SYMBOL2 && !g:mua";
}
~~~
