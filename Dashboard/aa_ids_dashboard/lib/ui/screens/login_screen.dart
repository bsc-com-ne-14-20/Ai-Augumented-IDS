import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '/state/auth_provider.dart';
import '../custom_widgets/login_card.dart';
import '../custom_widgets/logo.dart';
import 'dashboard_screen.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final TextEditingController _emailController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  bool _isLoading = false;

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  void _handleLogin() async {
    final email = _emailController.text.trim();
    final password = _passwordController.text.trim();

    final authProvider = context.read<AuthProvider>();

    if (email.isEmpty || password.isEmpty) {
      authProvider.setErrorMessage('Please fill in all fields');
      return;
    }

    // Clear previous errors
    authProvider.clearErrorMessage();
    setState(() => _isLoading = true);

    await authProvider.login(email, password);

    if (!mounted) return;

    if (authProvider.errorMessage != null) {
      setState(() => _isLoading = false);
      // Error will be displayed in the card on next rebuild
    } else if (authProvider.isAuthenticated) {
      // Keep loading state for 3 seconds then navigate
      await Future.delayed(const Duration(seconds: 3));
      if (!mounted) return;
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (context) => const DashboardScreen()),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final authProvider = context.watch<AuthProvider>();

    return Scaffold(
      backgroundColor: Theme.of(context).scaffoldBackgroundColor,
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24.0),
            child: LoginCard(
              logo: const IdsLogo(size: 80),
              buttonText: _isLoading ? "" : "SIGN IN",
              isLoading: _isLoading,
              usernameController: _emailController,
              passwordController: _passwordController,
              onLoginPressed: _handleLogin,
              errorMessage: authProvider.errorMessage,
            ),
          ),
        ),
      ),
    );
  }
}
