import 'package:azblob/azblob.dart';

Future<void> main() async {
  var storage = AzureStorage.parse('your connection string');
  await storage.putBlob('/yourcontainer/yourfile.txt', body: 'Hello, world.');
}
