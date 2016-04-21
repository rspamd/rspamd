Catena
======
Catena is a memory-consuming password scrambler that excellently
thwarts massively parallel attacks on cheap memory-constrained
hardware, such as recent graphical processing units (GPUs).
Furthermore, Catena provides resistance against cache-timing attacks, since
its memory-access pattern is password-independent.

Academic paper:
<a href="http://www.uni-weimar.de/fileadmin/user/fak/medien/professuren/Mediensicherheit/Research/Publications/catena-v3.1.pdf">catena-v3.1.pdf</a>

Rspamd specific
---------------

Rspamd implements Catena-Butterfly using full blake2b hash implemented in the
cryptobox.

Original code: https://github.com/medsec/catena