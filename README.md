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

The expression is defined as bytecode of a simple stack VM.


## Expressions

The opcodes are generated from simple arithmetic expressions with syntax TBD.

## Lockout prevention

The plan is to be able to statically verify that a given condition
leaves an opportunity for a valid set of Safe signers to disable the
Guard, if they choose so.  Because the VM opcode langauge is simple
and deliberately non-turing complete, it will always be possible to
guarantee correct verfication of Safe state after transaction and
ability to disable the guard.

Note: some users might choose to ignore this, either because they have
high confidence in their expression or becuase they have set up Safe
recovery.
