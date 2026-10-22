// loader bundle: StringTable joined at runtime, NO static .js ref to it.
var lang = document.documentElement.lang || "en";
$.getScript("jsAd/StringTable_" + lang + ".js");
