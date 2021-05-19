import java.io.FileReader;
import java.io.LineNumberReader;
import java.util.ArrayList;

import org.apache.datasketches.theta.UpdateSketch;
import org.apache.datasketches.theta.UpdateSketchBuilder;

/**
 * Sanity check class for the inflation attack included in the paper
 * On the Security of K Minimum Value (KMV) Sketches: Vulnerabilities and Protection
 * P. Reviriego, A. Sánchez-Macián, S. Liu, F. Lombardi
 * @author Alfonso Sánchez-Macián
 */
public class KMVAttackInflationFromFile {

	/**
	 * Reads the Attack sets from specific files, load them to sketches and check that 
	 * they provide the expected overestimation similar to the expected cardinality 
	 * @param args Command line arguments (ignored)
	 */
	public static void main (String[] args) {
		// cardinalities to be tested
		int[] cards = {10000, 28480, 81113, 231013, 657933, 1873817, 5336699, 15199111, 43287613, 123284674, 351119173, 1000000000};

		// Default initialization of the K minimum value.
		int K = 1024;
		// If arguments are passed, then K and randomness may not be taken the default values
		if (args.length>0) {
			try {
				// First argument is K and should be integer. Otherwise, 1024 will be used by default.
				K=Integer.parseInt(args[0]);
				System.out.println("Using K="+K);
			}catch(NumberFormatException nfe) {
				System.out.println("Format of K is not an integer, using K="+K);
			}			
		}

		// Number of experiments per cardinality. There should be a file per repetition
		int reps = 10;

		// Prefix and directory for the files containing the sets of elements

		String prefix = "aSet";
		String directory ="./";
		// Generate a Sketch Builder. By default it uses KMV
		UpdateSketchBuilder builder = UpdateSketch.builder();
		// Set K (1024 by default)
		builder.setNominalEntries(K);
		
		// For each of the cardinalities
		for (int cardinality:cards) {
			// Print cardinality to screen
			System.out.println("*****************************");
			System.out.println("Cardinality: " + cardinality);
			// Read a file per repetition and process it
			for (int iter=0;iter<reps;iter++) {
				// Print iteration number
				System.out.println("Iteration: " + iter);
				// Filename should be ./aSet[cardinality]_[iter].set
				// For instance aSet10000_0.set
				String filename = directory+prefix+cardinality+"_"+iter+".set";
				// Build the Attack set reading the elements from the file
				ArrayList<Double> aSet = buildFromFile(filename);
				// Calculate the metrics for the Attack set, loading them into an empty sketch.
				double[] metrics = validateSet(aSet, builder);
				// Print the estimation of the cardinality
				System.out.println("Estimation of cardinality of KMV with A: "+Math.round(metrics[0]));
			}
		}
	}

	/**
	 * Read the Attack set from a file. Elements are expected to be double values.  
	 * @param filename Name of the file to be read
	 * @return The attack set as an ArrayList of Doubles
	 */
	private static ArrayList<Double> buildFromFile(String filename){
		// Create an empty ArrayList
		ArrayList<Double> aSet = new ArrayList<Double>();
		try {
			// Read the file line by line using a LineNumberReader
			LineNumberReader lnr = new LineNumberReader(new FileReader(filename));
			String next = null;
			// Until no more lines in the file
			while((next = lnr.readLine())!=null) {
				// Convert the string to double and add it to the set.
				aSet.add(Double.parseDouble(next));
			}
			// close the reader
			lnr.close();
		}catch(Exception e) {
			e.printStackTrace();
		}
		// return the Attack set
		return aSet;
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
