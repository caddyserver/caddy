const AmazonDaxClient = require('amazon-dax-client');
var AWS = require("aws-sdk");

var region = "us-east-1";

// AWS.config.update({
//   region: region
// });

// var ddbClient = new AWS.DynamoDB.DocumentClient()

// var endpoint = "seconddax.t67iza.clustercfg.dax.use1.cache.amazonaws.com:8111";
var endpoint = "127.0.0.1:8111"

var dax = new AmazonDaxClient({endpoints: [endpoint], region: region});
var daxClient = new AWS.DynamoDB.DocumentClient({ service: dax });

var tableName = "aqfer-idsync";

var pk = "cid=c016,spid=mmsho.com,suu=15AB34BS232545VDd7841001";
var sk = "dpid=1";

var params = {
  TableName: tableName,
  Key:{
    "partition-key": pk,
    "sort-key": sk
  }
};

daxClient.get(params, function(err, data) {
  if (err) {
    console.log(err)
    //console.error("Unable to read item. Error JSON:", JSON.stringify(err, null, 2));
  } else {
    console.log("Data: ", data)
  }
});
