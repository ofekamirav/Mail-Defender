var API_BASE_URL = "https://unamputated-mousier-ervin.ngrok-free.dev";

var BRAND = {
  COLORS: {
    PRIMARY: "#0F9CF5",
    NAVY: "#102A43",
    SUCCESS: "#188038",
    WARNING: "#F59E0B",
    DANGER: "#D93025",
    GRAY: "#5F6368",
  },

  ICONS: {
    SAFE: "https://www.gstatic.com/images/icons/material/system/2x/verified_user_black_48dp.png",
    WARNING:
      "https://www.gstatic.com/images/icons/material/system/2x/warning_amber_48dp.png",
    DANGER:
      "https://www.gstatic.com/images/icons/material/system/2x/block_black_48dp.png",
    OFFLINE:
      "https://www.gstatic.com/images/icons/material/system/2x/cloud_off_black_48dp.png",
  },
};

function createProgressBar(percentage, colorHex) {
  var totalBlocks = 20;
  var filledBlocks = Math.round((percentage / 100) * totalBlocks);
  var emptyBlocks = totalBlocks - filledBlocks;
  var bar = "";
  for (var i = 0; i < filledBlocks; i++) bar += "■";
  for (var j = 0; j < emptyBlocks; j++) bar += "□";
  return '<font color="' + colorHex + '">' + bar + "</font>";
}

function buildAddOn(e) {
  try {
    var accessToken = e.messageMetadata.accessToken;
    var messageId = e.messageMetadata.messageId;

    GmailApp.setCurrentMessageAccessToken(accessToken);
    var message = GmailApp.getMessageById(messageId);

    var payload = {
      subject: message.getSubject() || "",
      body: message.getPlainBody() || "",
      sender: message.getFrom() || "",
    };

    var response = UrlFetchApp.fetch(API_BASE_URL + "/predict", {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true,
    });

    if (response.getResponseCode() !== 200) {
      return createErrorCard(
        "Server Error (" + response.getResponseCode() + ")"
      );
    }

    var json = JSON.parse(response.getContentText());
    return createResultCard(json);
  } catch (error) {
    return createErrorCard("Connection failed: " + error.toString());
  }
}

function createResultCard(data) {
  var label = data && data.label ? String(data.label) : "Unknown";
  var isPhishing = label === "Phishing";
  var isSuspicious = label === "Suspicious";
  var isSafe = !isPhishing && !isSuspicious;

  var theme = {
    title: "Verified Safe",
    color: BRAND.COLORS.SUCCESS,
    icon: BRAND.ICONS.SAFE,
    topLabel: "NO THREATS FOUND",
  };

  if (isPhishing) {
    theme = {
      title: "Phishing Detected",
      color: BRAND.COLORS.DANGER,
      icon: BRAND.ICONS.DANGER,
      topLabel: "CRITICAL THREAT",
    };
  } else if (isSuspicious) {
    theme = {
      title: "Suspicious Activity",
      color: BRAND.COLORS.WARNING,
      icon: BRAND.ICONS.WARNING,
      topLabel: "POTENTIAL RISK",
    };
  }

  var header = CardService.newCardHeader()
    .setTitle(theme.title)
    .setSubtitle("Mail Defender Detection")
    .setImageUrl(theme.icon);

  var mainSection = CardService.newCardSection();

  mainSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("Risk Assessment")
      .setText(
        '<b><font color="' +
          theme.color +
          '" size="4">' +
          theme.topLabel +
          "</font></b>"
      )
      .setWrapText(true)
      .setBottomLabel("Scanned at " + new Date().toLocaleTimeString())
  );

  var score = data && data.final_score != null ? Number(data.final_score) : 0;
  if (isNaN(score)) score = 0;
  var confidencePercent = (score * 100).toFixed(1);
  var progressBar = createProgressBar(Number(confidencePercent), theme.color);

  mainSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("Confidence")
      .setText(
        '<b><font color="' +
          theme.color +
          '">' +
          confidencePercent +
          "%</font></b>"
      )
      .setWrapText(true)
  );

  mainSection.addWidget(CardService.newTextParagraph().setText(progressBar));

  if (data && data.already_seen) {
    var source = (data.label_source || "").toString();
    var historyText =
      source === "user_feedback"
        ? "<b>Previously labeled by user</b>"
        : "Previously scanned";
    if (data.scan_count != null) {
      historyText += " · scans: <b>" + data.scan_count + "</b>";
    }

    mainSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("History")
        .setText(
          '<font color="' + BRAND.COLORS.GRAY + '">' + historyText + "</font>"
        )
        .setWrapText(true)
    );
  }

  var actionSection = CardService.newCardSection().setHeader("Actions");
  var buttonSet = CardService.newButtonSet();

  var markSafeAction = CardService.newAction()
    .setFunctionName("sendFeedbackLabel")
    .setParameters({ id: String(data.id || ""), is_phishing: "false" });

  var reportThreatAction = CardService.newAction()
    .setFunctionName("sendFeedbackLabel")
    .setParameters({ id: String(data.id || ""), is_phishing: "true" });

  var dangerText = isPhishing
    ? "⚠️ Confirm Threat"
    : isSuspicious
    ? "⚠️ Confirm Risk"
    : "⚠️ Report Threat";

  var safeText =
    data && data.label_source === "user_feedback"
      ? "✅ Change to Safe"
      : "✅ Mark Safe";

  buttonSet.addButton(
    CardService.newTextButton()
      .setText(safeText)
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setBackgroundColor(BRAND.COLORS.SUCCESS)
      .setOnClickAction(markSafeAction)
  );

  buttonSet.addButton(
    CardService.newTextButton()
      .setText(dangerText)
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setBackgroundColor(BRAND.COLORS.DANGER)
      .setOnClickAction(reportThreatAction)
  );

  actionSection.addWidget(buttonSet);

  var helperText = isSuspicious
    ? "If this is not risky, press <b>Mark Safe</b>. If it is risky, confirm."
    : "Help improve detection by confirming the result.";

  actionSection.addWidget(
    CardService.newTextParagraph().setText(
      '<small><font color="' +
        BRAND.COLORS.GRAY +
        '">' +
        helperText +
        "</font></small>"
    )
  );

  var builder = CardService.newCardBuilder()
    .setHeader(header)
    .addSection(mainSection)
    .addSection(actionSection);

  if (!isSafe) {
    var refreshAction = CardService.newAction().setFunctionName("buildAddOn");
    var footer = CardService.newFixedFooter().setPrimaryButton(
      CardService.newTextButton()
        .setText("Rescan Email")
        .setOnClickAction(refreshAction)
    );
    builder.setFixedFooter(footer);
  }

  return builder.build();
}

function sendFeedbackLabel(e) {
  var id = e.parameters.id || "";
  var isPhishing = e.parameters.is_phishing === "true";

  try {
    UrlFetchApp.fetch(API_BASE_URL + "/feedback", {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify({ id: id, is_phishing: isPhishing }),
      muteHttpExceptions: true,
    });

    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Feedback saved."))
      .build();
  } catch (err) {
    return CardService.newActionResponseBuilder()
      .setNotification(
        CardService.newNotification().setText("Connection Error")
      )
      .build();
  }
}

function createErrorCard(msg) {
  var header = CardService.newCardHeader()
    .setTitle("Connection Error")
    .setSubtitle("Mail Defender")
    .setImageUrl(BRAND.ICONS.OFFLINE);

  var refreshAction = CardService.newAction().setFunctionName("buildAddOn");

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText(msg))
        .addWidget(
          CardService.newTextButton()
            .setText("Try Again")
            .setOnClickAction(refreshAction)
        )
    )
    .build();
}
