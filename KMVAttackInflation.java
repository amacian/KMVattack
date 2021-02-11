import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Random;

import org.apache.datasketches.theta.UpdateSketch;
import org.apache.datasketches.theta.UpdateSketchBuilder;

/**
 * Main class for the inflation attack included in the paper
 * On the Security of K Minimum Value (KMV) Sketches: Vulnerabilities and Protection
 * P. Reviriego, A. Sánchez-Macián, S. Liu, F. Lombardi
 * It also stores the generated sets in a directory for later additional validations.
 * @author Alfonso Sánchez-Macián
 */
public class KMVAttackInflation {

	/**
	 * Implements the inflation algorithm from the paper for different cardinalities.
	 * Generates Attack sets with a reduced number of elements that, once inserted in
	 * a QuickSelect KMV Sketch, are estimated as bigger size sets.
	 * Sets are stored to file too. 
	 * @param args
	 */
	public static void main (String[] args) {
		// cardinalities to be tested
		int[] cards = {10000, 28480, 81113, 231013, 657933, 1873817, 5336699, 15199111, 43287613, 123284674, 351119173, 1000000000};
		
		// Number of experiments per cardinality to obtain the mean
		int reps = 10;

		// Filename prefix
		String prefix = "aSet";
		// Directory where the files will be stored
		String directory ="./";
		// Generate a Sketch Builder. By default it uses KMV
		UpdateSketchBuilder builder = UpdateSketch.builder();
		// Set K=1024
		builder.setNominalEntries(1024);
		
		// Set a random seed for reproducibility
		long repeat = 102030;
		Random random = new Random(repeat);
		  
		//For each cardinality
		for (int cardinality:cards) {
			  //Accummulate Isize, Asize and Estimations to calculate mean
			  long accumI = 0;
			  long accumA = 0;
			  long accumEst = 0;
			  
			  System.out.println("================================");
			  System.out.println("Cardinality of S: " + cardinality);
			  
			  // Repeat as many times as number of experiments defined per cardinality
			  for (int iter=0;iter<reps;iter++) {
				  String filename = directory+prefix+cardinality+"_"+iter+".set";
				  try {
					  PrintWriter fw = new PrintWriter(new FileWriter(filename));
					  // Create the set and retrieve I
					  ArrayList<Double> iSet = createSet(cardinality, builder, random);
					  
					  // Populate an empty sketch with I and calculate estimation
					  double[] metrics = validateSet(iSet, builder);
					  /*System.out.println("Size of I Set: " + iSet.size());
					  System.out.println("Estimation of cardinality of KMV with I: "+Math.round(metrics[0]));
					  System.out.println("Retained values with I: "+Math.round(metrics[1]));*/
		
					  // Reduce the I set to A
					  ArrayList<Double> aSet = reduceSet(iSet, builder);
					  /*System.out.println("Size of A Set: " + aSet.size());*/
					  
					// Populate an empty sketch with A and calculate estimation
					  metrics = validateSet(aSet, builder);
					  
					  // Accumulate I set size, A set size and estimation for A
					  accumI+=iSet.size();
					  accumA+=aSet.size();
					  accumEst+=Math.round(metrics[0]);
					  /*System.out.println("Estimation of cardinality of KMV with A: "+Math.round(metrics[0]));
					  System.out.println("Retained values with A: "+Math.round(metrics[1]));*/
					  for (int aidx=0; aidx<aSet.size(); aidx++) {
						  fw.println(aSet.get(aidx));
					  }
					  fw.close();
				  }catch(Exception e) {
					  e.printStackTrace();
				  }
			  }
			  // Calculate and print mean for this cardinality
			  System.out.println("Mean value for I elements: "+accumI/reps);
			  System.out.println("Mean value for A elements: "+accumA/reps);
			  System.out.println("Mean value for Estimation: "+accumEst/reps);
		  }	
	}

	/**
	 * Insert all the elements from the Attack set into an empty sketch and
	 * then calculates the estimation and the number of retained entries in the sketch.
	 * @param aAttack Attack set as an ArrayList
	 * @param builder Configured element in charge of building the sketch
	 * @return two double values corresponding to the estimate and the number of retained entries at the end of the loading process.
	 */
	private static double[] validateSet(ArrayList<Double> aAttack, UpdateSketchBuilder builder) {
		// Create and empty KMV sketch with the configuration defined outside of the function
		UpdateSketch sketch = builder.build();
		
		// Fill the sketch with each element of the array
		for (int i=0; i<aAttack.size(); i++) {
			double nextdob = aAttack.get(i);
			sketch.update(nextdob);
		}		
	
		// Calculate estimation and retained entries at the end of the fill process
		double[] metrics = {sketch.getEstimate(), sketch.getRetainedEntries()};
		// Return the calculated values
		return metrics;
	}

	/**
	 * Creates the original set with all the elements and calculates the initial reduced set I
	 * by including each element into the sketch and retaining only those that produce an increase
	 * in the estimation.
	 * @param finalCardinal Initial cardinality of the original set that will be reduced
	 * @param builder Configured element in charge of building the sketch
	 * @param random Generator of the finalCardinal elements in a pseudo-random way
	 * @return
	 */
	private static final ArrayList<Double> createSet (int finalCardinal, UpdateSketchBuilder builder, Random random){
		  
		// Create and empty KMV sketch with the configuration defined outside of the function
		UpdateSketch sketch = builder.build();
		
		// Get the original estimate (0)
		double estimate = sketch.getEstimate();
		
		// Prepare the i List with all the elements
		ArrayList<Double> iAttack = new ArrayList<Double>();

		// Generate a set of finalCardinal elements
		for (int i=0; i<finalCardinal; i++) {
			double nextdob = random.nextDouble();
			// Store them in the sketch
			sketch.update(nextdob);
			// If the new estimate is higher than the previous one, add it to I, otherwise ignore it
			if (sketch.getEstimate()>estimate) {
				iAttack.add(nextdob);
				estimate=sketch.getEstimate();
			}
		}
		/*System.out.println("Estimation of cardinality of the original set: " + Math.round(estimate));
		System.out.println("Retained entries: " + sketch.getRetainedEntries());*/
		
		// return I set
		return iAttack;
		
	}
	
	/**
	 * Creates a more reduced Attack set A from the initial reduced set I
	 * by reversing the set, including each element into the sketch and retaining only those that produce an increase
	 * in the estimation.
	 * @param iAttack Initial attack set as an ArrayList that will be further reduced.
	 * @param builder Configured element in charge of building the sketch
	 * @return
	 */
	public static final ArrayList<Double> reduceSet (ArrayList<Double> iAttack, UpdateSketchBuilder builder){

		// Create and empty KMV sketch with the configuration defined outside of the function
		UpdateSketch sketch = builder.build();
		// Get the original estimate (0)
		double estimate = sketch.getEstimate();
		// Prepare the a List with all the elements 
		ArrayList<Double> aAttack = new ArrayList<Double>();
		// Reverse the order of the list (we could also traverse it backwards) 
		Collections.reverse(iAttack);
		// for each index less than the size of the list
		for (int i=0; i<iAttack.size(); i++) {
			// Get the next element
			double nextdob = iAttack.get(i);
			// Update the sketch
			sketch.update(nextdob);
			// If the new estimation is higher than the previous one, add the element to A
			if (sketch.getEstimate()>estimate) {
				  aAttack.add(nextdob);
				  estimate=sketch.getEstimate();
			}
		}
		
		// May not be necessary (it has no impact on the result)
		Collections.reverse(aAttack);
		
		// Return A
		return aAttack;
	}
}
