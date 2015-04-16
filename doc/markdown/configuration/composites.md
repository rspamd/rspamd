# Rspamd composite symbols

## Introduction

Rspamd composites are used to combine rules and create more complex rules.
Composite rules are defined by `composite` keys. The value of this key should be
an object that defines composite's name and value, which is the combination of rules
in a joint expression.

For example, you can define a composite that is added when two of symbols are found:

~~~nginx
composite {
	name = "TEST_COMPOSITE";
	expression = "SYMBOL1 and SYMBOL2";
}
~~~

In this case, if a message has `SYMBOL1` and `SYMBOL2` simultaneously then they are replaced by
symbol `TEST_COMPOSITE`. The weights of `SYMBOL1` and `SYMBOL2` are substracted from the metric
accordingly.

## Composite expression

You can use the following operations in a composite expression:

* `AND` `&` - matches true only if both of operands are true
* `OR` `|` - matches true if any of operands are true
* `NOT` `!` - matches true if operand is false

You also can use braces to define priorities. Otherwise operators are evaluated from left to right.
For example:

~~~nginx
composite {
    name = "TEST";
    expression = "SYMBOL1 and SYMBOL2 and ( not SYMBOL3 | not SYMBOL4 | not SYMBOL5 )";
}
~~~

Composite rule can include other composites in the body. There is no restriction of definition order:
~~~nginx
composite {
    name = "TEST1";
    expression = "SYMBOL1 AND TEST2";
}
composite {
    name = "TEST2";
    expression = "SYMBOL2 OR NOT SYMBOL3";
}
~~~

Composites should not be recursive and it is normally detected by rspamd.

## Composite weights rules
Composites can leave the symbols in a metric or leave their weights. That could be used to create
non-captive composites.
For example, you have symbol `A` and `B` with weights `W_a` and `W_b` and a composite `C` with weight `W_c`.

* If `C` is `A & B` then if rule `A` and rule `B` matched then these symbols are *removed* and their weights are removed as well, leading to a single symbol `C` with weight `W_c`.
* If `C` is `-A & B`, then rule `A` is preserved, but the symbol `C` is inserted. The weight of `A` is preserved as well, so the total weight of `-A & B` will be `W_a + W_c`.
* If `C` is `~A & B`, then rule `A` is *removed* but its weight is *preserved*, leading to a single symbol `C` with weight `W_a + W_c`

