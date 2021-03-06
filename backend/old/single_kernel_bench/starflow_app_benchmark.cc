// simplified starflow application benchmark. 


#include <raft>
#include <raftio>

#include "kernels/microflow_reader.h"
// #include "kernels/clfr_reader.h"
// #include "kernels/clfr_counter.h"

// // All-metric calculator.
// #include "kernels/all_metrics.h"

// Metric calculator with integrated GPV reader.
#include "kernels/merged_all_metrics.h"
// Something to pipe to...
#include "kernels/benchmark_printer.h"

// Arg parsing.
#include "inputparser.h"

// // Apps.
// // Profiler.
// #include "kernels/host_timing_profiler.h"
// // Micro-burst detector.
// #include "kernels/microburst_detector.h"
// // Metric measurement and app label
// #include "kernels/performance_metrics_and_app_label.h"

// // Feature calculators.
// #include "kernels/rich_feature_calculator.h"
// #include "kernels/netflow_feature_calculator.h"
// #include "kernels/pfe_feature_calculator.h"
// #include "kernels/allstats_feature_calculator.h"





// // Utilities.
// #include "kernels/cloner.h"

// #include "kernels/clfr_counter_chain.h"

// #include "kernels/clfr_counter_replicated.h"

// #include "kernels/benchmark_printer.h"


#include <cstdint>
#include <iostream>
#include <fstream>
#include <string>




// void runSimpleCounter();
// void runHostProfiler();
// void runClassifiers();
// void runMicroburstDetector();

// void runClones(int N);
// void runChains(int N);
// void runReplicas(int N);

// void benchmarkReplicas();

// New files 11/19
void benchmarkReplicasFromDigests();
void runMetricGeneratorFromDigests(int N, int metricSet);


/*=================================
=            Arguments            =
=================================*/

int nReplicas = 1; // Number of replica pipelines. Each uses 2 cores.
int mSet = 1; // Metric set.
/**
 *
 * metric sets:
 * 1: 4 streaming metrics.
 * 2: 20 streaming metrics.
 * 3: +application class.
 * 4: +host profiles.
 * 5: +full queue occupants.
 */

void parseArgs(int argc, char *argv[]){
  char * ptr_nReplicas = getCmdOption(argv, argv+argc, "-r");
  if (ptr_nReplicas != 0) {
    nReplicas = atoi(ptr_nReplicas);
  }
  char * ptr_mSet = getCmdOption(argv, argv+argc, "-m");
  if (ptr_mSet != 0) {
    mSet = atoi(ptr_mSet);
  }
  std::cout << "#---arguments---" <<std::endl;
  std::cout << "nReplicas="<<nReplicas<<std::endl;
  std::cout << "mSet="<<mSet<<std::endl;

}


/*=====  End of Arguments  ======*/


int main(int argc, char** argv)
{
  parseArgs(argc, argv);
  benchmarkReplicasFromDigests();
  return 0;
}

/*======================================
=            new code 11/19            =
======================================*/
// Run replicas directly from digest.
// Removed training from online component of classifier.
// Working on complete example that outputs records with
// all features.




void benchmarkReplicasFromDigests(){
  // 11/19 -- benchmark replica pipelines directly from digests.

  // Benchmark every metric set.
  // output: 
  // msetReplicaCtReplicaRate -- mSet : replica Ct : replica Id : replica rate
  // std::cout << "msetReplicaCtReplicaRate = {}"  << std::endl;
  // std::cout << "msetReplicaCtReplicaRate["<<mSet<<"]={}"<<std::endl;
  std::cout << "clfrCount = {}" << std::endl;
  std::cout << "clfrRate = {}" << std::endl;
  std::cout << "#testing " << nReplicas << " replicas" << endl;
  std::cout << "# ------------ " << endl;
  runMetricGeneratorFromDigests(nReplicas, mSet); // populate clfrRate.
  std::cout << "# ------------ " << endl;  
  std::cout << "msetReplicaCtReplicaRate["<<mSet<<"]["<<nReplicas<<"]={'clfrRates':clfrRate, 'clfrCounts':clfrCount}"<<std::endl;
}

void runMetricGeneratorFromDigests(int N, int metricSet) {
  // Calculate metrics from GPV digests.
  raft::map m;  

  starflow::kernels::BenchmarkPrinter<double> logger(N);
  starflow::kernels::MetricBackend<starflow::kernels::MicroflowReader::output_t> * sinks[N];
  for (int i=0; i<N; i++){
    sinks[i] = new starflow::kernels::MetricBackend<starflow::kernels::MicroflowReader::output_t>(metricSet, i, "/home/jsonch/gits/starflow_analytics/inputs/mCLFRs.32.bin");
    m += *(sinks[i]) >> logger[std::to_string(i)];
  }
  m.exe();  


  // raft::map m;  

  // starflow::kernels::MicroflowReader * readers[N];
  // starflow::kernels::MetricBackend<starflow::kernels::MicroflowReader::output_t> * sinks[N];
  // for (int i=0; i<N; i++){
  //   readers[i] = new starflow::kernels::MicroflowReader("/home/jsonch/gits/starflow_analytics/inputs/mCLFRs.32.bin", i);
  //   sinks[i] = new starflow::kernels::MetricBackend<starflow::kernels::MicroflowReader::output_t>(metricSet);
  //   m += *(readers[i]) >> *(sinks[i]);
  // }
  // m.exe();  
}

/*=====  End of new code 11/19  ======*/


// /*===============================================
// =            Functionality test code            =
// ===============================================*/

// void runSimpleCounter(){
//   raft::map m;
//   std::cout << "initializing kernels." << endl;
//   // The kernel to read CLFRs. Emits CLFRs generated by converter.
//   starflow::kernels::ClfrReader reader("/home/jsonch/gits/starflow_analytics/inputs/caida2015_02_dirA.mCLFRs.bin.clfrs");
//   // starflow::kernels::ClfrReader reader("/home/jsonch/gits/starflow_analytics/inputs/mCLFRs.32.bin.clfrs");  
//   starflow::kernels::ClfrCounter<starflow::kernels::MicroflowReader::output_t> counter;
//   m += reader >> counter;
//   m.exe();
//   return;
// }


// void runHostProfiler(){
//   raft::map m;
//   std::cout << "initializing kernels." << endl;
//   starflow::kernels::ClfrReader reader("/home/jsonch/gits/starflow_analytics/inputs/caida2015_02_dirA.mCLFRs.bin.clfrs");
//   starflow::kernels::HostProfiler<starflow::kernels::MicroflowReader::output_t> profiler("/home/jsonch/gits/starflow_analytics/outputs/timingProfile.bin", 5 * 60 * 1000);
//   m += reader >> profiler;  
//   m.exe();
//   return;
// }
// void runClassifiers(){
//   raft::map m;
//   std::cout << "initializing kernels." << endl;
//   starflow::kernels::ClfrReader reader("/home/jsonch/gits/starflow_analytics/inputs/caida2015_02_dirA.mCLFRs.bin.clfrs");
//   // // Compute clfr features. 
//   // starflow::kernels::FeatureCalculator<starflow::kernels::ClfrReader::output_t> calculator;

//   // Compute netflow features.
//   // starflow::kernels::NetFlowFeatureCalculator<starflow::kernels::ClfrReader::output_t> calculator;

//   // Compute PFE aggregatable features.
//   // starflow::kernels::PFEFeatureCalculator<starflow::kernels::ClfrReader::output_t> calculator;

//   // Compute complex aggregated stat features.
//   // starflow::kernels::AllStatsFeatureCalculator<starflow::kernels::ClfrReader::output_t> calculator;
//   // m += reader >> calculator;  
//   // m += reader >> calculator;  
//   m.exe();

// }
// void runMicroburstDetector(){
//   raft::map m;
//   std::cout << "initializing kernels." << endl;
//   starflow::kernels::ClfrReader reader("/home/jsonch/gits/starflow_analytics/inputs/microburst.clfrs.bin");

//   starflow::kernels::MicroburstDetector<starflow::kernels::ClfrReader::output_t> detector;
//   m += reader >> detector;  
//   m.exe();
// }


// /*=====  End of Functionality test code  ======*/