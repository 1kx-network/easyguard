# Easy Transaction Guard for Safe{Wallet}

Safe{Wallet} [Transaction Guards](https://docs.safe.global/advanced/smart-account-guards) is a mechanism that allows checking whether a transaction can or cannot be executed.

It allows owners of Safe to set policies governing the use of a
Safe. It restricts what can be done with a Safe.

Using Transaction Guards, one can implement various policies. For
example, we can reqiure not only that a guard should have enough
signers, but that it should have particular signers in case some
signers have higher authority than others.

Or, we can allow certain operations to all signers, and others in case
particular signers are prensent.

Guards are potentially very useful, but they are exceedingly rarely
used, for multiple reasons:

1. You need to develop and deploy a guard contract.
2. This contract needs to be secure:
    - it must not lock you out
    - the condition it checks needs to be correct

This makes Guards really diffucult to use.

This project's aim is to make it simpler.

They key idea is that there could be singleton Guard contract, which
could be set for any Safe. The condition to check is then programmed
by using a simple expression that consists of addresses of owners,
signers, address constants, and boolean and arithmetic expressions.

The expression is represented by an EVM code deployed as a separate
contract.  Importantly, this code is sanitized by the guard before
being deployed, so that we have a guarantee that it can do nothing
other than its intended purpose:

 - It can access memory, stack, storage.
 - It *cannot* make any calls.
 - It can access CALLDATA, so it will see any arguments passed to it.
 - JUMP/JUMPI is supported, thus conditions of any complexity are possible.


## Expressions

The opcodes are generated from simple arithmetic expressions with syntax TBD.

## Lockout prevention

TBD

Lockout prevention is more difficult in an EVM-based
implementation, but is still possible. We can do best effort symbolic
compuation on it (client-side), and if we are able to give a
conclusive answer, we'll give it. If we are not able to do this, we'll
warn the user before deploying the contract.
