const express = require("express");
const request = require("request");
const crypto = require("crypto");
const uuid = require("uuid");
const {exec} = require("child_process");
const https = require("https");
const querystring = require("querystring");
const fs = require("fs");

var port = process.env.PORT || 3000;
var app = express();

var hospitaldb = undefined;
var bearerToken = undefined;

/* Twitter info: @PPE_Donations, foreverdevtesting1@gmail.com */
const TWITTER_QUERY_DELTATIME = 22;
const TWITTER_PUBLIC_APP_KEY  = "LXb0G7lz2YrFDGitD7HXfuLjE";
const TWITTER_PRIVATE_APP_KEY = "AI1k2QMbC3l720mj96lWoUKOIkmFtLzvPQPO4wmiU1kAbLDRt9";
const TWITTER_PUBLIC_ACCESS_KEY = "1249635192588906496-Ex70fz5hjzFQDP3eHJi8AUycHHHb28";
const TWITTER_PRIVATE_ACCESS_KEY = "fvweyXVi8GQIzVQlz7kRs6HEMWVlUErKs5UcX0HNE1iN2";
const TWITTER_CURL = 'curl -u ' + TWITTER_PUBLIC_APP_KEY + ':' + TWITTER_PRIVATE_APP_KEY + ' --data "grant_type=client_credentials" "https://api.twitter.com/oauth2/token"';

function allowCrossDomain(req, res, next) {
	res.header("Access-Control-Allow-Origin", "*");
	res.header("Access-Control-Allow-Method", "GET,PUT,POST,OPTIONS");
	res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, Content-Length, X-Requested-With");

	/* intercept OPTIONS */
	if (req.method == "OPTIONS") {
		res.send(200);
	} else {
		next();
	}
}

function extractHospitalJSON(hospitalData) {
	return {
		name:      hospitalData.NAME || "( ? )",
		latitude:  hospitalData.LATITUDE || 0,
		longitude: hospitalData.LONGITUDE || 0,
		address:   hospitalData.ADDRESS || "( ? )",
		city:      hospitalData.CITY || "( ? )",
		state:     hospitalData.STATE || "( ? )",
		zip:       hospitalData.ZIP || "( ? )",
		website:   hospitalData.WEBSITE || "( ? )"
	};
}

function getSingleNearestHospital(lat, lon) {
	var hospitals = hospitaldb.features;
  var smallestDist = 1000;
  var closestHospital = undefined;
  for (var i in hospitals) {
    var prop = hospitals[i].properties;
    var hospLat = prop.LATITUDE;
    var hospLon = prop.LONGITUDE;
    var dist = Math.sqrt(Math.pow(hospLat - lat, 2) + Math.pow(hospLon - lon, 2));
    if (dist < smallestDist) {
      smallestDist = dist;
			closestHospital = extractHospitalJSON(prop);
    }
  }
  return [closestHospital];
}

function getNearestHospitalsN(lat, lon, n) {
	var hospitals = hospitaldb.features;
	hospitals.sort(function(a, b) {
		var propa = a.properties;
		var propb = b.properties;
		
		var coorda = [propa.LATITUDE, propa.LONGITUDE];
		var coordb = [propb.LATITUDE, propb.LONGITUDE];

		var da = Math.sqrt(Math.pow(coorda[0] - lat, 2) + Math.pow(coorda[1] - lon, 2));
		var db = Math.sqrt(Math.pow(coordb[0] - lat, 2) + Math.pow(coordb[1] - lon, 2));
		
		return (da < db) ? -1 : (da > db) ? 1 : 0;
	});

	var nearestHospitals = [];
	for (var i = 0; i < n; i++) {
		nearestHospitals.push(extractHospitalJSON(hospitals[i].properties));
	}

	return nearestHospitals;
}

function processHospitalQuery(lat, lon, n) {
	var num = n || 1;

	if (num == 1) {
		return getSingleNearestHospital(lat, lon);
	} else {
		return getNearestHospitalsN(lat, lon, n);
	}
}

/* creates a Twitter authentication string that is needed in the
 * 'Authorization' header for every single API call.
 * see: https://developer.twitter.com/en/docs/basics/authentication/oauth-1-0a/authorizing-a-request
 *
 * httpMethod: GET or POST
 * baseURL: the twitter api URL, e.g. https://api.twitter.com/update.json
 * queryParams: dictionary of query parameters */
function createTwitterAuthenticationString(httpMethod, baseURL, queryParams) {

	/* the seven values needed for authentication.  see link above for more details */
	var oauth_values = {
		oauth_consumer_key:        TWITTER_PUBLIC_APP_KEY,
	  oauth_nonce:               uuid.v4().replace(/\W/g, ""),
		oauth_signature:           undefined,
	  oauth_signature_method:    "HMAC-SHA1",
	  oauth_timestamp:           Math.round((new Date()).getTime() / 1000),
	  oauth_token:               TWITTER_PUBLIC_ACCESS_KEY,
	  oauth_version:             "1.0"
	} 
	
	/* performs percent-encoding according to RFC 3986, Section 2.1 */ 
	var encodeRFC3986 = function(str) {
		return encodeURIComponent(str).replace(/[!'()*]/g, function(c) {
			return '%' + c.charCodeAt(0).toString(16);
		});
	}
	
	/* ========================================================================== */
	/* signature generation */	
	/* see: https://developer.twitter.com/en/docs/basics/authentication/oauth-1-0a/creating-a-signature */

	/* percent encode every key, value (including query parameters) */	
	var allKeys = {};
	for (var i in queryParams) {
		allKeys[encodeRFC3986(i)] = encodeRFC3986(queryParams[i]);
	}
	for (var i in oauth_values) {
		if (oauth_values[i] == undefined) {
			continue;
		}
		allKeys[encodeRFC3986(i)] = encodeRFC3986(oauth_values[i]);
	}

	/* alphabetically sort keys.  this is necessary for authentication */
	const ordered = {}
	Object.keys(allKeys).sort().forEach(function(key) {
		ordered[key] = allKeys[key];
	});
	allKeys = ordered;
	
	/* append all query params and oauth_values to paramString */
	var paramString = "";
	for (var key in allKeys) {
		paramString += (key + "=" + allKeys[key]);
		paramString += "&";
	}
	paramString = paramString.substring(0, paramString.length - 1);

	/* generate signature base string, see link above */
	var sigBaseString = httpMethod.toUpperCase();
	sigBaseString += "&";
	sigBaseString += encodeRFC3986(baseURL);
	sigBaseString += "&";
	sigBaseString += encodeRFC3986(paramString);

	/* generate signingKey, which is used as the secret SHA1 encription key */
	var signingKey = encodeRFC3986(TWITTER_PRIVATE_APP_KEY);
	signingKey += "&";
	signingKey += encodeRFC3986(TWITTER_PRIVATE_ACCESS_KEY);

	/* perform HMAC-SHA1 hashing on sigBaseString, with signingKey as the key...
	 * also perform base64 encoding on the hex-array result */
	var hmac = crypto.createHmac("sha1", signingKey);
	hmac.update(sigBaseString);
	oauth_values.oauth_signature = Buffer.from(hmac.digest("hex"), "hex").toString("base64");
	
	/* ========================================================================== */
	/* signature generation is complete.  Now, we can generate the authentication string */

	var DST = "OAuth ";
	for (var key in oauth_values) {
		DST += (encodeRFC3986(key) + '="' + encodeRFC3986(oauth_values[key]) + '", ');
	}
	DST = DST.substring(0, DST.length - 2);

	return DST; 
}

function getAverageCoordinates(coords) {
	const avg = {
		latitude: 0.0,
		longitude: 0.0
	};
	for (var i in coords) {
		avg.latitude += coords[i][1]/coords.length;
		avg.longitude += coords[i][0]/coords.length;
	} 
	return avg;
}

function sendTweet(targetUser, enabledLocationServices, lat, lon) {

	var tweetStatus;

	var camelCaseName = function(str) {
		str = str.toLowerCase().split(" ");
		for (var i = 0; i < str.length; i++) {
			str[i] = str[i][0].toUpperCase() + str[i].substr(1);
		}
		return str.join(" ");
	}

	if (!enabledLocationServices) {
		tweetStatus = "Hey @" + targetUser + ", we can't see where you are!" +
		              "  Please turn on your location sharing settings and tweet at" +
									" us again on a mobile device with your location attached.  If you'd like to keep your" +
									" location private or can't use a mobile device, check out our website: <link>"
	} else {
		var nearestHospital = getSingleNearestHospital(lat, lon)[0];
		tweetStatus = "Hey, @" + targetUser + "!  The hospital closest to you is " +
		              camelCaseName(nearestHospital.name) + ".  They are located at " + 
									camelCaseName(nearestHospital.address) + ", " + camelCaseName(nearestHospital.city) +
									", " + nearestHospital.state + " " + nearestHospital.zip + ".  " +
									"You can find their contact information on their website: " + nearestHospital.website; 
	}

	const url = "https://api.twitter.com/1.1/statuses/update.json";
	const form = {
		status: tweetStatus
	};
	const authString = createTwitterAuthenticationString("POST", url, form);
	const headers = {
		Authorization: authString
	}

	request.post({url: url, form: form, headers: headers}, function(err, res, body) {
		if (res.statusCode == 200) {
			console.log("successfully posted tweet: " + tweetStatus);
		} else {
			console.log("failed to post tweet to user " + targetUser);
		}
	});
}

function pullTwitterMentions() {

	const url = "https://api.twitter.com/1.1/statuses/mentions_timeline.json";	
	const query = {
		tweet_mode: "extended",
		count: 20
	};
	const authString = createTwitterAuthenticationString("GET", url, query);
	const headers = {
		Authorization: authString
	};

	var twitterDateToTimestamp = function(twitterDate) {
		return Math.round(new Date(Date.parse(twitterDate.replace(/( \+)/, " UTC$1"))).getTime() / 1000);
	}

	request({url: url, qs: query, headers: headers}, function(err, res, body) {

		if (err) {
			console.log("Twitter pull error: " + err);
			return;
		}
		if (res.statusCode != 200) {
			console.log("Got bad status code from Twitter: " + res.statusCode);
			console.log("Got body: " + body);
			return;
		}
		
		/* if the tweet was within TWITTER_QUERY_DELTATIME, it must be
		 * a new tweet.  anything older must have been processed in
		 * a previous iteration */
		var returnedMentions = JSON.parse(body);
		var timestamp = Math.round((new Date()).getTime() / 1000);
		var didFindNewTweet = false;
		for (var i in returnedMentions) {
			var mention = returnedMentions[i];
			var mention_timestamp = twitterDateToTimestamp(mention.created_at);
			if (Math.abs(timestamp - mention_timestamp) <= TWITTER_QUERY_DELTATIME) { 
				didFindNewTweet = true;
				console.log("found new tweet: " + mention.full_text);
				if (mention.place != null) {
					var averageCoords = getAverageCoordinates(mention.place.bounding_box.coordinates[0]);
					sendTweet(mention.user.screen_name, true, averageCoords.latitude, averageCoords.longitude);
				} else {
					sendTweet(mention.user.screen_name, false);
				}
			}
		}		
		if (!didFindNewTweet) {
			console.log("no new tweets found...");
		}
	});

}

function initDatabase() {
  let rawdata = fs.readFileSync("hospitaldb.json");
  hospitaldb = JSON.parse(rawdata);
	console.log("database read successfully");
}

initDatabase();

/* CRITICAL -- Allow cross domain requests */
app.use(allowCrossDomain);

app.get("/", function(req, res) {
  res.send("Hello, world!");
});

app.get("/queryhospitals/", function(req, res) {
  var query = querystring.parse(req.url.split("?")[1]);
  if (query.lat == undefined || query.lon == undefined) {
    res.send(JSON.stringify({
      success: false,
      message: "latitude or longitude missing.",
			hospitals: []
    }));
    return;
  }
  var hospData = processHospitalQuery(query.lat, query.lon, query.n);
  res.send(JSON.stringify({
    success: true,
    hospitals: hospData
  }));
}); 

app.listen(port, function() {
  console.log("Server is now listening for requests!");
});

exec(TWITTER_CURL, function(err, stdout, stderr) {
	if (err) {
		console.log("Error getting Twitter bearer token: " + err);
		return;
	}
	bearerToken = JSON.parse(stdout);
	console.log("successfully got bearer token from Twitter");
	console.log(stdout);
});

setInterval(pullTwitterMentions, TWITTER_QUERY_DELTATIME * 1000);
