Hey friends I have an idea for a way to make neural networks deterministiclly instead of probabilistically.

Right now we train neural networks on unstructured data but the problem is they are probabilistic models and hard to understand.

I want to create a new neural network that is fully understandable, and each weight is intentional.

So what we do is this. We create a neural network that specializes in reading, understanding and writing actual neural network weights.

So the idea is that a correctly trained network could actually intentionally create and update neural networks with new knowledge deterministically.

So like you could say "create a network that can read mnist", and it would like actually know how to make the network *including the weights*, and it would come up with reasonable values for the weights in the network. It would specify each nerve and each connection with the actual value of the weight.

The cool thing about this is we could have it like gain an intuition for various neural architectures. it would set weights, assign input values, run it through, and "debug" so it would get better and better at making neural nets.

Honestly, we could have it like do reinforcement learning where every time it makes updates that are better it can be like "yes"! and it will reward itself by doing reinforcement learning for that series, and we do this in parallel and the ones that work win.

So the benefit would be for safety sensitive scenarios, having an ai that can truly understand and inspect what weights mean and what they are for, and ability to edit them for precise purpose. This would prevent a surgery robot, for example, from having neurons left over poorly set from bad training cutting too much because it saw a video in pretraining about a butcher shop.

The other benefit is that it could intelligently do what our brains do - create "skip" connections from early layers to later layers enhancing efficiency.

It could also lead to enhanced efficiency where it only makes a few connections that are necessary. It could also choose data types intelligently using high precision floating points for areas that are sensitive and need it, and low precision elsewhere.

By training a network to be able to inspect and make networks, we can get much closer to guaranteeing that networks don't have rogue neorons.

Since networks have billions of neurons, I would guess that it would need to do inspection of neurons at high levels and low levels bit by bit and a ton of work and experimentation on different sections and sort of create a plain text "database" of what sections refer to what, it could make indexes and stuff like that.

Eventually a neural network could be "self compiling" like a language where it doesn't even need a pretraining phase or backprop.