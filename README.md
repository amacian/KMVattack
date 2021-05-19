# Attacks for a K Minimum Value Sketch implementation

This repository includes the code in Java of the Inflation and Deflation attacks over the Apache DataSketckes implementation as used for the paper:

P. Reviriego, A. Sánchez-Macián, S. Liu and F. Lombardi "On the Security of K Minimum Value (KMV) Sketches and its Implementation-independent Vulnerabilities", under submission to IEEE Transactions on Dependable and Secure Computing.

# Dependencies
Apache DataSketckes Java Core API > 1.3.0

# Content
*src* directory includes the following files:
- KMVAttackInflation.java (to perform the inflation attack and generate the Attack sets)
- KMVAttackDeflation.java (to perform the deflation attack)
- KMVAttackInflationFromFile.java (reads the attack sets generated by KMVAttackInflation, and perform a validation from an empty sketch)

*doc* includes the Javadoc files for the classes.

*ideal* implementation of the ideal KMV sketch in Matlab for the simulations.

# Execution of the code
Compile and execute the appropriate Java class depending on the type of attack to be simulated.
If different cardinalities, t values or iterations are required, just change the variables in the Java classes, recompile and execute.

