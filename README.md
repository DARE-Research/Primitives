# Experimentation to Optimize Alloy Primitives

(honestly idk what I'm doing, but you never know what you are doing until you try anyway, so who cares)
don't tell anyone but this is just an excuse for me to learn simd stuff(idk what it's)

## What's This All About?

This project is a wild ride into the world of primitive optimization. We're throwing ideas at the wall and seeing what sticks. Our main weapon of choice? SIMD (Single Instruction, Multiple Data) - because why not make things go zoom?

## Design Choice

## The Grand Plan (or lack thereof)
0. Early support for arm neon
1. Take a look at Alloy primitives
2. Scratch our heads and wonder how to make them faster
3. Remember that SIMD exists and seems cool
4. Try to apply SIMD to... something. Anything, really.
5. See what happens and hope for the best
6. Implement Vector operations


## How to Join This Chaos

1. Clone this repo
2. Install... things. (We'll figure out what exactly later)
3. Run some code and see if it explodes
4. If it doesn't explode, check if it's faster
5. If it's faster, celebrate! If not, pretend you meant to do that

## Results So Far
# Benchmark Comparison

| Primitive | SIMD(Primitives) | Alloy Primitives | Performance Change |
|-----------|-----------|--------------|--------------------|
| address/checksum | 169.43 ns | 201.41 ns | Faster by ~23% |
| bytes/32 | 13.818 ns | 15.818 ns | Faster by ~14% |
| bytes/64 | 14.614 ns | 17.667 ns | Faster by ~21% |
| bytes/128 | 36.106 ns | 36.859 ns | Slightly faster by ~2% |
| bytes/256 | 42.191 ns | 41.024 ns | Slower by ~2.8% |



## SIMD  Results for Parity Inversion

We've recently added SIMD optimizations for Parity inversion. Here are the benchmark results:

| Input Size | Alloy Primitives| SIMD Version |  Performance Change |
|------------|-----------------|--------------|---------------------|
| 10         | 21.235 ns       | 23.258 ns    | Slower by ~9.53%    |
| 100        | 101.93 ns       | 85.767 ns    | Faster by ~15%      |
| 1000       | 974.07 ns       | 722.84 ns    | Faster by ~25%      |
| 10000      | 10.090 μs       | 8.007 μs     | Faster by ~20%      |


Key observations:
- SIMD shows overhead for very small inputs(stick with the non simd version)
- Performance gains become significant for larger inputs (1000+)
- Consistent ~20-25% improvement for large inputs



## Contribute

Got ideas? Throw them in! 
Know what you're doing? Even better, we could use the help!

## License

Probably something open source. We'll figure it out.

## Acknowledgements

This project is inspired by the Alloy primitives developed by the Paradigm team. We aim to build upon their work to further optimize Ethereum's core functionality.

(They seem to know what they're doing, unlike us)

By the DARE research team, you've never heard of it I know but give it a year... nahhh I mean two years.