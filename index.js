/* jshint node: true, devel: true */
'use strict';

const
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),
  request = require('request'),
  n = require('nonce')(),
  oauthSignature = require("oauth-signature"),
  qs = require("qs"),
  async = require("async");

var yelpConsumerKey = process.env.YELP_CONSUMER_KEY;
var yelpConsumerSecret = process.env.YELP_CONSUMER_SECRET;
var yelpToken = process.env.YELP_TOKEN;
var yelpTokenSecret = process.env.YELP_TOKEN_SECRET;

var global_context = {};

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));


const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);
  }
});

app.post('/webhook', function (req, res) {
  var data = req.body;
  if (data.object == 'page') {
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });
    res.sendStatus(200);
  }
});

app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query['account_linking_token'];
  var redirectURI = req.query['redirect_uri'];
  var authCode = "1234567890";
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});


function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}


function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;


  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam,
    timeOfAuth);

  sendTextMessage(senderID, "Authentication successful");
}


function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:",
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    console.log("Received echo for message %s and app %d with metadata %s",
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);

    sendTextMessage(senderID, "Quick reply tapped");
    return;
  }

  if (messageText) {
    switch (messageText) {
      case 'image':
        sendImageMessage(senderID);
        break;

      case 'gif':
        sendGifMessage(senderID);
        break;

      case 'audio':
        sendAudioMessage(senderID);
        break;

      case 'video':
        sendVideoMessage(senderID);
        break;

      case 'file':
        sendFileMessage(senderID);
        break;

      case 'button':
        sendButtonMessage(senderID);
        break;

      case 'generic':
        sendGenericMessage(senderID);
        break;

      case 'receipt':
        sendReceiptMessage(senderID);
        break;

      case 'quick reply':
        sendQuickReply(senderID);
        break;

      case 'read receipt':
        sendReadReceipt(senderID);
        break;

      case 'typing on':
        sendTypingOn(senderID);
        break;

      case 'typing off':
        sendTypingOff(senderID);
        break;

      case 'account linking':
        sendAccountLinking(senderID);
        break;

      default:
        respondToMessageText(senderID, messageText);
    }
  } else if (messageAttachments) {
    if (messageAttachments[0].payload != null && messageAttachments[0].payload.hasOwnProperty('coordinates')) {
      sendLocationMessage(senderID, messageAttachments);
    } else {
      sendTextMessage(senderID, "Message with attachment received");
    }
  }
}

function respondToMessageText(recipientId, messageText) {
  printDebugStatement(recipientId, "In function respondToMessageText()");
  messageIntent = getMessageIntent(messageText)
  if (messageIntent in ["HELLO", "GET_STARTED"]) {
    sendHiMessage(recipientId);
  } else if (messageIntent == "GET_PREFERRED_CUISINE") {
    sendPreferredCuisineMessage(recipientId);
  } else if (messageIntent == "DEBUG_ON") {
    debugOn(recipientId);
  } else if (messageIntent == "DEBUG_OFF") {
    debugOff(recipientId);
  } else if (messageIntent == "RESET") {
    resetUserContext(recipientId);
  } else if (messageIntent == 'RESTAURANT') {
    sendRestaurantMessage(recipientId, messageText);
  }
}

function debugOn(recipientId) {
  checkUserInGlobalContext(recipientId, false);
  global_context[recipientId]['debug'] = true;
  printDebugStatement(recipientId, "Turning debug statements on");
}

function debugOff(recipientId) {
  checkUserInGlobalContext(recipientId, false);
  printDebugStatement(recipientId, "Turning debug statements off");
  global_context[recipientId]['debug'] = false;
}

function resetUserContext(recipientId) {
  checkUserInGlobalContext(recipientId, false);
  printDebugStatement(recipientId, "Resetting user context");
  checkUserInGlobalContext(recipientId, true);
}

function getMessageIntent(recipientId, messageText) {
  checkUserInGlobalContext(recipientId, false);
  printDebugStatement(recipientId, "In function respondToMessageText()");
  mt = messageText.toLowerCase();
  if (mt == "preferred cuisine") {
    intent = "GET_PREFERRED_CUISINE";
  } else if (mt in ["hi", "hello", "hey"]) {
    intent = "HELLO";
  } else if (mt == "get started") {
    intent = "GET_STARTED";
  } else if (mt == "debug on") {
    intent = "DEBUG_ON";
  } else if (mt == "debug off") {
    intent = "DEBUG_OFF";
  } else if (mt == "debug reset") {
    intent = "RESET";
  } else {
    intent = "RESTAURANT";
  }
  printDebugStatement(recipientId, "Intent is: " + intent);
  return intent;
}

function sendHiMessage (recipientId) {
	checkUserInGlobalContext(recipientId, true);
  printDebugStatement(recipientId, "In function sendHiMessage()");
	var url = "https://graph.facebook.com/v2.6/"+recipientId+"?access_token="+PAGE_ACCESS_TOKEN;
	request(url, function(error, response, body) {
		if (!error && response.statusCode == 200) {
			body = JSON.parse(body);
			var first_name = body.first_name;
			var output_text = "Hi "+first_name+"! What would you like me to pick you today? (eg. \"Pick me a mexican restaurant\").";

		    var messageData = {
		      recipient: {
		        id: recipientId
		      },
		      message: {
		        text: output_text,
		        metadata: "DEVELOPER_DEFINED_METADATA"
		      }
		    };

		    callSendAPI(messageData);
		}
	})
}


function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s",
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}



function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " +
    "at %d", senderID, recipientID, payload, timeOfPostback);

  checkUserInGlobalContext(senderID, false);
  printDebugStatement(senderID, "In function receivedPostback()");

	if (payload == "USER_DEFINED_PAYLOAD") {
		sendHiMessage(senderID);
	}

	if (payload == "WHATTIME_TONIGHT") {
		global_context[senderID]['time'] = "Tonight";
		sendRestaurantMessage(senderID, "Tonight");
	}
	if (payload == "WHATTIME_NOW") {
		global_context[senderID]['time'] = "Now";
		sendRestaurantMessage(senderID, "Now");
	}

	if (payload == "7:45" || payload == "8:45" || payload == "9:30") {
    printDebugStatement(senderID, "The payload was a time, booking reservation (mock)");

    // TODO: store username in global_context, and check before sending the username
    // request, so only have to query for it once (will make responses to user faster.)

	  var url = "https://graph.facebook.com/v2.6/"+senderID+"?access_token="+PAGE_ACCESS_TOKEN;
	  request(url, function(error, response, body) {
		  if (!error && response.statusCode == 200) {
  			body = JSON.parse(body);
  			var messageData = {
  			  recipient: {
  				id: senderID
  			  },
  			  message: {
  				text: "Ok, "+body.first_name+". The restaurant is booked for tonight at "+payload+".\nOh, by the way, you earned a 10% discount by booking with PickMe. Enjoy!",
  				metadata: "DEVELOPER_DEFINED_METADATA"
  			  }
  			};
  		   callSendAPI(messageData);
  		}
    });
	}

}

function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}



function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

function checkUserInGlobalContext(recipientId, reset) {
  if (!(recipientId in global_context)) {
    global_context[recipientId] = {
      preferred_cuisine: "",
      location_lat: "",
      location_long: "",
	    time: "",
      debug: false
    };
  }
  if (reset == true) {
	  global_context[recipientId] = {
        preferred_cuisine: "",
        location_lat: "",
        location_long: "",
		    time: "",
        debug: false
      };
  }
}

// - debug_statement(debug_text)
//     - calls checkUserInGlobalContext()
//     - makes a statement text: "DEBUG LOG: ..."
//     - writes this text to console.log
//     - if debug is on for user, writes the text to user using callSendAPI
function printDebugStatement(userId, debugText) {
  checkUserInGlobalContext(userId, false);
  console.log(debugText);
  if (global_context[userId]['debug']) {
    var messageData = {
      recipient: {
        id: userId
      },
      message: {
        text: debugText,
        metadata: "DEVELOPER_DEFINED_METADATA"
      }
    };
    callSendAPI(messageData);
  }
}

function getCuisineType(recipientId, messageText) {

  var cuisine_list = ["mexican", 'italian', 'chinese', 'korean',
  'japanese', 'american', 'french', 'german', 'sushi', 'indian', 'thai',
  'russian', 'south african'];
  var cuisine_type = false;
  var normalized_messageText = messageText.toLowerCase();

  for (var i = 0; i < cuisine_list.length; i++) {
    var cuisine = cuisine_list[i]
    if (normalized_messageText.indexOf(cuisine) !== -1) {
      cuisine_type = cuisine;
      checkUserInGlobalContext(recipientId, false)
      global_context[recipientId]['preferred_cuisine'] = cuisine;
      // preferred_cuisine = cuisine;
    }
  }

  return cuisine_type;
}

function sendPreferredCuisineMessage(recipientId) {

  var output_text = "No preferred cuisine specified";

  checkUserInGlobalContext(recipientId, false)
  printDebugStatement(recipientId, "In function sendPreferredCuisineMessage()");
  var preferred_cuisine = global_context[recipientId]['preferred_cuisine']
  if (preferred_cuisine != "") {
    output_text = "Preferred cuisine is " + preferred_cuisine;
  }

  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: output_text,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}


function sendRestaurantMessage(recipientId, messageText) {
  checkUserInGlobalContext(recipientId, false);
  printDebugStatement(recipientId, "In function sendRestaurantMessage()");

  // Get cuisine.
  // Replace this with watson to get intent and entity.
  var cuisine = getCuisineType(recipientId, messageText);

  var have_cuisine = (global_context[recipientId]['preferred_cuisine'] != "");
  var have_location = (global_context[recipientId]['location_lat'] != "");
  var have_time = (global_context[recipientId]['time'] != "")

  var restaurantMessageText = "";

  if (have_cuisine && have_location) {
	  if (have_time) {
		 sendMessageToUserFromYelpResult(recipientId);
	 } else {
		 sendAskForTimeMessage(recipientId);
	 }
  } else {
    if (have_location) {
      restaurantMessageText = "What type of food would you like to eat? (eg. Mexican food).";
    } else {
      restaurantMessageText = "Where are you? (use the location button)";
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          text: restaurantMessageText,
          metadata: "DEVELOPER_DEFINED_METADATA"
        }
      };
    }
  }
  callSendAPI(messageData);
}

function sendMessageToUserFromYelpResult(recipientId) {
  checkUserInGlobalContext(recipientId, false)

  var preferred_cuisine = global_context[recipientId]['preferred_cuisine'];
  var location_lat = global_context[recipientId]['location_lat'];
  var location_long = global_context[recipientId]['location_long'];
	yelpMakeQuery("meat", preferred_cuisine, {lat: location_lat, long: location_long}, 10000, function(result) {
		var messageData = {
		  recipient: {
			id: recipientId
		  },
		  message: {
			text: "I highly recommend this place. It has great " + preferred_cuisine + " food.",
			metadata: "DEVELOPER_DEFINED_METADATA"
		  }
		};
    var mapMessageData = {
      recipient: {
        id: recipientId
      },
      message: {
          attachment: {
              type: "template",
              payload: {
                  template_type: "generic",
                  elements: {
                      element: {
                          title: result.name,
                          image_url: "https:\/\/maps.googleapis.com\/maps\/api\/staticmap?size=764x400&center="+result.latitude+","+result.longitude+"&zoom=25&markers="+result.latitude+","+result.longitude,
                          item_url: "http:\/\/maps.apple.com\/maps?q="+result.latitude+","+result.longitude+"&z=16"
                      }
                  }
              }
          }
      }
    };

	async.waterfall([
		function(cb) {
			callSendAPI(messageData);
			cb(null);
		},
		function(cb) {
			callSendAPI(mapMessageData);
			cb(null);
		}
	],
function(err, result) {
	if (global_context[recipientId]['time'] == "Tonight") {
		sendBookingTimeMessage(recipientId);
	} else {
		var message = {
		  recipient: {
			id: recipientId
		  },
		  message: {
			text: "We just booked a table for you in 15 minutes. Enjoy!",
			metadata: "DEVELOPER_DEFINED_METADATA"
		  }
		};
	   callSendAPI(messageData);
	}
});
  });
}

/*
 * Send get the GPS location and send a confirmation via the Send API.
 *
 */
function sendLocationMessage(senderID, messageAttachments) {
  checkUserInGlobalContext(senderID, false);
  printDebugStatement(senderID, "In function sendLocationMessage()");

  var location_lat = messageAttachments[0].payload.coordinates.lat;
  var location_long = messageAttachments[0].payload.coordinates.long;
  global_context[senderID]['location_lat']  = location_lat;
  global_context[senderID]['location_long'] = location_long;

  var preferred_cuisine = global_context[senderID]['preferred_cuisine'];
  var time = global_context[senderID]['time'];
  if (preferred_cuisine != "") {
	  if (time != "") {
		  sendMessageToUserFromYelpResult(senderID);
	  } else {
		  sendAskForTimeMessage(senderID);
	  }
	  return;
  }

  var locationMessageText = "What kind of food would you like?";

  var messageData = {
    recipient: {
      id: senderID
    },
    message: {
      text: locationMessageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}









function sendAskForTimeMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "When do you want to go there?",
          buttons:[{
            type: "postback",
            title: "Now",
            payload: "WHATTIME_NOW"
          }, {
            type: "postback",
            title: "Tonight",
            payload: "WHATTIME_TONIGHT"
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}



function sendBookingTimeMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
		attachment: {
			type: "template",
			payload: {
				template_type: "button",
				text: "These times are available for booking, would look like me to do it for you?",
				buttons:[{
					type: "postback",
					title: "7:45",
					payload: "7:45"
				},
				{
					type: "postback",
					title: "8:45",
					payload: "8:45"
				},
				{
					type: "postback",
					title: "9:30",
					payload: "9:30"
				}
			]
		}
	}
}
};

callSendAPI(messageData);

}

















function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/rift.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}


function sendGifMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/instagram_logo.gif"
        }
      }
    }
  };

  callSendAPI(messageData);
}


function sendAudioMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "audio",
        payload: {
          url: SERVER_URL + "/assets/sample.mp3"
        }
      }
    }
  };

  callSendAPI(messageData);
}


function sendVideoMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "video",
        payload: {
          url: SERVER_URL + "/assets/allofus480.mov"
        }
      }
    }
  };

  callSendAPI(messageData);
}


function sendFileMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "file",
        payload: {
          url: SERVER_URL + "/assets/test.txt"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "When do you want to go there?",
          buttons:[{
            type: "postback",
            title: "Now",
            payload: "DEVELOPED_DEFINED_PAYLOAD"
          }, {
            type: "postback",
            title: "Tonight",
            payload: "DEVELOPED_DEFINED_PAYLOAD"
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}


function sendGenericMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "rift",
            subtitle: "Next-generation virtual reality",
            item_url: "https://www.oculus.com/en-us/rift/",
            image_url: SERVER_URL + "/assets/rift.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/rift/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "touch",
            subtitle: "Your Hands, Now in VR",
            item_url: "https://www.oculus.com/en-us/touch/",
            image_url: SERVER_URL + "/assets/touch.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/touch/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for second bubble",
            }]
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}


function sendReceiptMessage(recipientId) {
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",
          timestamp: "1428444852",
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: SERVER_URL + "/assets/riftsq.png"
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: SERVER_URL + "/assets/gearvrsq.png"
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}



function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What's your favorite movie genre?",
      metadata: "DEVELOPER_DEFINED_METADATA",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]
    }
  };

  callSendAPI(messageData);
}


function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}


function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}


function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}


function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}


function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s",
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s",
        recipientId);
      }
    } else {
      console.error(response.error);
    }
  });
}

var yelpMakeQuery = function(term, type, location, radius, callback) {
	var httpMethod = 'GET';
    var url = 'https://api.yelp.com/v2/search/';
    var parameters = {
        oauth_consumer_key: yelpConsumerKey,
		oauth_nonce: n(),
		oauth_signature_method: 'HMAC-SHA1',
		oauth_timestamp: n().toString().substr(0,10),
        oauth_token: yelpToken,
		term: term,
		limit: 12,
		radius_filter: radius,
		category_filter: type
    };
	if (typeof location == "string") {
		parameters.location = location;
	} else if (typeof location == "object") {
		if (location.hasOwnProperty("lat") && location.hasOwnProperty("long")) {
			parameters.ll = parseFloat(location.lat) + "," + parseFloat(location.long);
		}
	}
    var consumerSecret = yelpConsumerSecret;
    var tokenSecret = yelpTokenSecret;
    var signature = oauthSignature.generate(httpMethod, url, parameters, consumerSecret, tokenSecret, { encodeSignature: false});
	parameters.oauth_signature = signature;
	var paramUrl = qs.stringify(parameters);
	var queryUrl = url + "?" + paramUrl;

	request(queryUrl, function(error, response, body) {
		if (!error && response.statusCode == 200) {
			yelpParseResponseBody(JSON.parse(body), function(result) {
				callback(yelpReturnFormattedResult(result));
			});
		} else {
			console.log("Error getting response from Yelp");
		}
	});
};

var yelpParseResponseBody = function(body, callback) {
	var total = 0;
	var result;

	if (body.hasOwnProperty("businesses")) {
		total = body.businesses.length;
		result = body.businesses[0];
		body.businesses.forEach(function(business) {
			total -= 1;
			if (business.hasOwnProperty("rating") && business.hasOwnProperty("review_count")) {
				if (business.rating > result.rating && business.review_count > 20) {
					result = business;
				}
			}
			if (total <= 0) {
				callback(result);
			}
		});
	}
};

var yelpReturnFormattedResult = function(result) {
	var res = {
		name: result.name,
		rating: result.rating,
	};
	if (result.hasOwnProperty('phone')) { res.phone = result.phone; }
	if (result.hasOwnProperty('image_url')) { res.image = result.image_url; }
	if (result.hasOwnProperty('location')) {
		res.street = result.location.address[0];
		res.city = result.location.city;
		if (result.location.hasOwnProperty("cross_streets")) {
			res.crossroad = result.location.cross_streets;
		}
		if (result.location.hasOwnProperty("coordinate")) {
			res.latitude = result.location.coordinate.latitude;
			res.longitude = result.location.coordinate.longitude;
		}
	}
	if (result.hasOwnProperty('is_closed')) { res.is_closed = result.is_closed; }
	return (res);
};



app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
