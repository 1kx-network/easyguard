# EasyGuard Project Guide

## Build & Test Commands
```
# Install dependencies
npm install

# Compile contracts
npx hardhat compile

# Run all tests
npx hardhat test

# Run specific test
npx hardhat test test/EasyGuard.test.ts

# Deploy contracts
npx hardhat run scripts/deploy.ts
```

## Code Style Guidelines
- **Solidity**: v0.8.28, using solidity-style-guide
- **TypeScript**: Use strict typing with interfaces and types
- **Naming**: 
  - Variables: camelCase
  - Functions: camelCase 
  - Contracts: PascalCase
- **Imports**: Group by external/internal, alphabetize
- **Error Handling**: Use require statements with descriptive messages
- **Documentation**: Use NatSpec for all public interfaces
- **Testing**: All functions should be covered by tests
- **Gas Optimization**: Enable optimizer in hardhat.config.ts

## Project Structure
- `contracts/`: Solidity contracts
- `test/`: Test files
- `scripts/`: Deployment scripts