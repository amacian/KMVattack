import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import org.apache.datasketches.theta.UpdateSketch;
import org.apache.datasketches.theta.UpdateSketchBuilder;

/**
 * Main class for the deflation attack included in the paper
 * On the Security of K Minimum Value (KMV) Sketches: Vulnerabilities and Protection
 * P. Reviriego, A. Sánchez-Macián, S. Liu, F. Lombardi
 * @author Alfonso Sánchez-Macián
 */
public class KMVAttackDeflation {

	/**
	 * Implements the deflation algorithm from the paper for different values of t.
	 * Generates Attack sets with a big number of elements that, once inserted in
	 * a QuickSelect KMV Sketch, are estimated as smaller size sets.
	 * @param args Command line arguments (ignored)
	 */
	public static void main (String[] args) {
		// Values of t to be tested [limiting the number of elements added to the sketch]
		int[] tvals = {100, 1514, 2929, 4343, 5757, 7171, 8586, 10000};
		
		// Number of experiments per t to obtain the mean
		int reps = 10;//0;

		// Expected size of the Attack Set
		int expectedSize=100000;
		
		// Filename 
		String prefix = "resultDeflation.txt";
		// Directory where the file will be stored
		String directory ="./";

		// Nominal entries for the sketch
		int K = 1024;
		
		// Generate a Sketch Builder. By default it uses QuickSelect KMV
		UpdateSketchBuilder builder = UpdateSketch.builder();
		
		// Set K=1024
		builder.setNominalEntries(K);
		
		// Set a random seed for reproducibility
		long repeat = 102030;
		Random random = new Random(repeat);
		
		// Build the filename
		String filename = directory+prefix;
		
		try {
			// Use a PrintWriter to write to file
			PrintWriter fw = new PrintWriter(new FileWriter(filename));

			//For each t
			for (int t:tvals) {
				  // Accummulate Asize, Estimations and number of elements from S tested to generate A
				  // to calculate mean
				  long accumA = 0;
				  long accumEst = 0;
				  long accumTested = 0;
				  
				  // Print to file and screen
				  fw.println("================================");
				  fw.println("T: " + t);
				  System.out.println("================================");
				  System.out.println("T: " + t);
				  
				  // Repeat as many times as number of experiments defined (for each t) 
				  for (int iter=0;iter<reps;iter++) {
					  // Generate a set with a big number of unique elements
					  Set<Double> sSet = generateS(10000000, random);
					  // Attack set to be filled
					  ArrayList<Double> aSet = new ArrayList<Double>();
	
					  // Create the sketch
					  UpdateSketch sketch = builder.build();
					  
					  // Initialize the j and inc variables from the algorithm
					  int j=0;
					  int inc = 0;
					 
					  // Initialize the number of elements from S that were used
					  // to generate A
					  int tested = 0;
					  
					  // Calculate the estimate from the sketch (should be 0)
					  double estimate = sketch.getEstimate();
					  
					  // Traverse the set and get each element
					  for (double val:sSet) {
						  // increment j (inc=1 when the first element does not produce 
						  // an increment of estimates)
						  j=j+inc;
						  // one additional element from the set is used
						  tested++;
						  // update the sketch with the value from the set.
						  sketch.update(val);
						  // if the value does not increase the estimate value
						  if (sketch.getEstimate()==estimate) {
							  // set inc to 1 as an element has been found that it
							  // does not increment the estimate.
							  inc=1;
							  // Add the value to the Attack set A
							  aSet.add(val);
							  
							  // When A reaches the expected size, stop traversing the set
							  if (aSet.size()==expectedSize) {
								  break;
							  }
						  // The estimate has increased. Modify the stored value.
						  }else {
							  estimate = sketch.getEstimate();
						  }
						  
						  // When j reaches K+t, clear the sketch and continue with an empty one
						  if(j > K+t) {
							  //System.out.println(sketch.toString());
							  sketch.reset();
							  // reset j and inc
							  j=0;
							  inc=0;
							  // reset the estimate
							  estimate = sketch.getEstimate();
						  }
						  
					  }
					  
					  
					  // Populate an empty sketch with A and calculate estimation
					  double[] metrics = validateSet(aSet, builder);
					  
					  // print to file and screen
					  System.out.println("Estimation of cardinality of KMV with A: "+Math.round(metrics[0]));
					  System.out.println("Retained values with A: "+Math.round(metrics[1]));
					  System.out.println("Tested values in S: "+ tested);
					  fw.println("Estimation of cardinality of KMV with A: "+Math.round(metrics[0]));
					  fw.println("Retained values with A: "+Math.round(metrics[1]));
					  fw.println("Tested values in S: "+ tested);
					  fw.flush();
					  // Accumulate I set size, A set size and estimation for A
					  accumA+=aSet.size();
					  accumEst+=Math.round(metrics[0]);
					  accumTested+=tested;
				  }
				  // Calculate and print mean for this cardinality
				  fw.println("Mean value for A elements: "+accumA/reps);
				  fw.println("Mean value for Estimation: "+accumEst/reps);
				  fw.println("Mean value for tested: "+accumTested/reps);
				  fw.flush();
				  System.out.println("Mean value for A elements: "+accumA/reps);
				  System.out.println("Mean value for Estimation: "+accumEst/reps);
				  System.out.println("Mean value for tested: "+accumTested/reps);
			  }	
			  fw.close();
		  }catch(Exception e) {
			  e.printStackTrace();
		  }
	}

	/**
	 * Creates the original set with all the unique elements.
	 * @param size Size of the set
	 * @param random Generator of the finalCardinal elements in a pseudo-random way
	 * @return the Set of unique elements
	 */
	public static final Set<Double> generateS (int size, Random random){
		// Create the Set 
		Set<Double> s = new HashSet<Double>();
		
		// Add elements to the set until the expected size is reached.
		while (s.size()<size) {
			double nextdob = random.nextDouble();
			s.add(nextdob);
		}

		return s;
		
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
}
