# Experimentation to Optimize Ethereum Primitives

(honestly idk what I'm doing, but you never know what you are doing until you try anyway, so who cares)
don't tell anyone but this is just an excuse for me to learn simd stuff(idk what it's)

## What's This All About?

This project is a wild ride into the world of primitive optimization. We're throwing ideas at the wall and seeing what sticks. Our main weapon of choice? SIMD (Single Instruction, Multiple Data) - because why not make things go zoom?

## The Grand Plan (or lack thereof)
0. Early suuport for arm neon
1. Take a look at Ethereum primitives
2. Scratch our heads and wonder how to make them faster
3. Remember that SIMD exists and seems cool
4. Try to apply SIMD to... something. Anything, really.
5. See what happens and hope for the best


## How to Join This Chaos

1. Clone this repo
2. Install... things. (We'll figure out what exactly later)
3. Run some code and see if it explodes
4. If it doesn't explode, check if it's faster
5. If it's faster, celebrate! If not, pretend you meant to do that

## Results So Far
# Benchmark Comparison

|
 Primitive 
|
 SIMD(Primitives)
|
 Alloy Primitives
|
 Performance Change 
|
|
-----------
|
-----------
|
------------
|
---------------------
|
|
 address/checksum 
|
 171.87 ns 
|
 201.41 ns 
|
 Faster by ~17% 
|
|
 bytes/32 
|
 13.818 ns 
|
 15.818 ns 
|
 Faster by ~14% 
|
|
 bytes/64 
|
 14.614 ns 
|
 17.667 ns 
|
 Faster by ~21% 
|
|
 bytes/128 
|
 36.106 ns 
|
 36.859 ns 
|
 Slightly faster by ~2% 
|
|
 bytes/256 
|
 42.191 ns 
|
 41.024 ns 
|
 Slower by ~2.8%
|


But hey, that's what experimentation is all about, right?

## Contribute

Got ideas? Throw them in! 
Know what you're doing? Even better, we could use the help!

## License

Probably something open source. We'll figure it out.

## Acknowledgements

This project is inspired by the Alloy primitives developed by the Paradigm team. We aim to build upon their work to further optimize Ethereum's core functionality.

(They seem to know what they're doing, unlike us)