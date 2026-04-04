package io.confluent.csfle.crosscloud;

import io.confluent.csfle.crosscloud.app.CrossCloudConsumer;
import io.confluent.csfle.crosscloud.app.CrossCloudProducer;
import io.confluent.csfle.crosscloud.app.DekSyncApp;
import io.confluent.csfle.crosscloud.app.DestinationConsumerAwsAttempt;
import io.confluent.csfle.crosscloud.app.SplitProvisionDstApp;
import io.confluent.csfle.crosscloud.app.SourceConsumer;
import io.confluent.csfle.crosscloud.app.SourceConsumerGcpAttempt;

import java.util.Arrays;

/**
 * Dispatcher — selects the run mode from the first CLI argument.
 *
 * Usage:
 *   java -jar cross-cloud-csfle.jar provision                        deployment/deployment.properties
 *   java -jar cross-cloud-csfle.jar provision-dst                    deployment/deployment.properties
 *   java -jar cross-cloud-csfle.jar producer                         deployment/deployment.properties
 *   java -jar cross-cloud-csfle.jar consumer                         deployment/deployment.properties
 *   java -jar cross-cloud-csfle.jar sync                             deployment/deployment.properties
 *   java -jar cross-cloud-csfle.jar source-consumer                  deployment/deployment.properties
 *   java -jar cross-cloud-csfle.jar source-consumer-gcp-attempt      deployment/deployment.properties
 *   java -jar cross-cloud-csfle.jar destination-consumer-aws-attempt deployment/deployment.properties
 *
 * Backward-compat: if no mode keyword is given, the first argument is treated
 * as a properties path and the provisioner runs (original CrossCloudCsfleRunner behaviour).
 */
public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("Usage: java -jar cross-cloud-csfle.jar [provision|provision-dst|producer|consumer|sync|source-consumer|source-consumer-gcp-attempt|destination-consumer-aws-attempt] <deployment.properties>");
            System.exit(1);
        }

        String mode = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);

        switch (mode) {
            case "provision"                         -> CrossCloudCsfleRunner.main(rest);
            case "provision-dst"                     -> SplitProvisionDstApp.main(rest);
            case "producer"                          -> CrossCloudProducer.main(rest);
            case "consumer"                          -> CrossCloudConsumer.main(rest);
            case "sync"                              -> DekSyncApp.main(rest);
            case "source-consumer"                   -> SourceConsumer.main(rest);
            case "source-consumer-gcp-attempt"       -> SourceConsumerGcpAttempt.main(rest);
            case "destination-consumer-aws-attempt"  -> DestinationConsumerAwsAttempt.main(rest);
            default                                  -> CrossCloudCsfleRunner.main(args); // backward compat
        }
    }
}
