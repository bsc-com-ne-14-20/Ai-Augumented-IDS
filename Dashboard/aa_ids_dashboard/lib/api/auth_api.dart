import 'package:http/http.dart' as http;
import 'package:aa_ids_dashboard/api/endpoints.dart';

class AuthApi {
  /// Makes an HTTP request to authenticate the user.
  Future<bool> login(String email, String password) async {
  //   try {
  //     final response = await http.post(
  //       Uri.parse(ApiEndpoints.login),
  //       headers: {
  //         'Content-Type': 'application/json',
  //       },
  //       body: jsonEncode({
  //         'email': email,
  //         'password': password,
  //       }),
  //     );

  //     if (response.statusCode == 200) {
  //       return true;
  //     } else {
  //       final Map<String, dynamic> errorData = jsonDecode(response.body);
  //       throw Exception(errorData['message'] ?? errorData['detail'] ?? 'Invalid email or password');
  //     }
  //   } catch (e) {
  //     rethrow;
  //   }
  // }
    return true;
  }
}