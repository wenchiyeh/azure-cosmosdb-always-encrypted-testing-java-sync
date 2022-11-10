package com.function;

import java.util.*;
import com.microsoft.azure.functions.annotation.*;
import com.microsoft.azure.functions.*;
//import com.azure.cosmos.ConsistencyLevel;
import com.azure.security.keyvault.keys.cryptography.KeyEncryptionKeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.core.credential.TokenCredential;
import com.azure.cosmos.encryption.CosmosEncryptionClientBuilder;
import com.azure.cosmos.encryption.CosmosEncryptionClient;
import com.azure.cosmos.encryption.CosmosEncryptionAsyncClient;
import com.azure.cosmos.encryption.CosmosEncryptionDatabase;
import com.azure.cosmos.encryption.CosmosEncryptionAsyncDatabase;
import com.azure.cosmos.models.EncryptionKeyWrapMetadata;
import com.azure.cosmos.CosmosClientBuilder;
import com.azure.cosmos.CosmosClient;
import com.azure.cosmos.CosmosAsyncClient;
//import com.azure.cosmos.CosmosContainer;
//import com.azure.cosmos.CosmosDatabase;
//import com.azure.cosmos.CosmosException;
/**
 * Azure Functions with HTTP Trigger.
 */
public class HttpTriggerJava1 {
    /**
     * This function listens at endpoint "/api/HttpTriggerJava1". Two ways to invoke it using "curl" command in bash:
     * 1. curl -d "HTTP Body" {your host}/api/HttpTriggerJava1
     * 2. curl {your host}/api/HttpTriggerJava1?name=HTTP%20Query
     */
    @FunctionName("HttpTriggerJava1")
    public HttpResponseMessage run(
            @HttpTrigger(name = "req", methods = {HttpMethod.GET, HttpMethod.POST}, authLevel = AuthorizationLevel.ANONYMOUS) HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {
        /*context.getLogger().info("Java HTTP trigger processed a request.");

        // Parse query parameter
        String query = request.getQueryParameters().get("name");
        String name = request.getBody().orElse(query);

        if (name == null) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body("Please pass a name on the query string or in the request body").build();
        } else {
            return request.createResponseBuilder(HttpStatus.OK).body("Hello, " + name).build();
        }*/

        TokenCredential tokenCredential = new DefaultAzureCredentialBuilder()
            .build();
        KeyEncryptionKeyClientBuilder keyEncryptionKeyClientBuilder =
            new KeyEncryptionKeyClientBuilder().credential(tokenCredential);

        CosmosClient client = new CosmosClientBuilder()
            .endpoint("myEndpoint")
            .key("myKey")
            .buildClient();

        CosmosEncryptionClient cosmosEncryptionClient =
            new CosmosEncryptionClientBuilder().cosmosClient(client).keyEncryptionKeyResolver(keyEncryptionKeyClientBuilder)
                .keyEncryptionKeyResolverName(CosmosEncryptionClientBuilder.KEY_RESOLVER_NAME_AZURE_KEY_VAULT).buildClient();

        CosmosEncryptionDatabase cosmosEncryptionDatabase = cosmosEncryptionClient
            .getCosmosEncryptionDatabase("myDB");

        EncryptionKeyWrapMetadata metadata = new EncryptionKeyWrapMetadata(
            cosmosEncryptionClient.getKeyEncryptionKeyResolverName(), 
            "mycmk", 
            "myKeyVault",
            EncryptionAlgorithm.RSA_OAEP.toString());

            cosmosEncryptionDatabase.rewrapClientEncryptionKey(
            "my-dek",
            metadata);
       

        return request.createResponseBuilder(HttpStatus.OK).body("Hello3").build();
    }
}
