
import 'package:flutter/material.dart';
import 'package:aa_ids_dashboard/ui/theming/app_colors.dart'; // Import AppColors

class LoginCard extends StatelessWidget {
  final Widget logo;
  final String title;
  final String usernameLabel;
  final String? usernameHint;
  final String passwordLabel;
  final String? passwordHint;
  final String buttonText;
  final TextEditingController? usernameController;
  final TextEditingController? passwordController;
  final VoidCallback? onLoginPressed;
  final ValueChanged<String>? onUsernameChanged;
  final ValueChanged<String>? onPasswordChanged;
  final bool isLoading;
  final String? errorMessage;

  const LoginCard({
    super.key,
    required this.logo,
    this.title = "AA-IDS Login",
    this.usernameLabel = "Username",
    this.usernameHint = "Enter username",
    this.passwordLabel = "Password",
    this.passwordHint = "Enter password",
    this.buttonText = "Login",
    this.usernameController,
    this.passwordController,
    this.onLoginPressed,
    this.onUsernameChanged,
    this.onPasswordChanged,
    this.isLoading = false,
    this.errorMessage,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 8,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(10),
      ),
      child: Container(
        width: 400, //  make this responsive if needed
        padding: const EdgeInsets.all(32),
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(10),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Logo
            logo,

            const SizedBox(height: 24),

            // Title
            Text(
              title,
              style: Theme.of(context).textTheme.headlineLarge?.copyWith(fontSize: 24),
            ),

            const SizedBox(height: 32),

            // Error Card
            if (errorMessage != null && errorMessage!.isNotEmpty)
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: AppColors.highThreat.withOpacity(0.15),
                  border: Border.all(
                    color: AppColors.highThreat.withOpacity(0.5),
                  ),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    const Icon(
                      Icons.error_outline,
                      color: AppColors.highThreat,
                      size: 20,
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        errorMessage!,
                        style: const TextStyle(
                          color: AppColors.highThreat,
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ],
                ),
              ),

            if (errorMessage != null && errorMessage!.isNotEmpty)
              const SizedBox(height: 24),

            // Username Field
            Align(
              alignment: Alignment.centerLeft,
              child: Text(
                usernameLabel,
                style: Theme.of(context).textTheme.bodyMedium,
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: usernameController,
              onChanged: onUsernameChanged,
              style: const TextStyle(color: AppColors.textPrimary),
              decoration: InputDecoration( // uses InputDecorationTheme as defined
                hintText: usernameHint,
              ),
            ),

            const SizedBox(height: 20),

            // Password Field
            Align(
              alignment: Alignment.centerLeft,
              child: Text(
                passwordLabel,
                style: Theme.of(context).textTheme.bodyMedium,
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: passwordController,
              onChanged: onPasswordChanged,
              obscureText: true,
              style: const TextStyle(color: AppColors.textPrimary),
              decoration: InputDecoration( // Leverage InputDecorationTheme
                hintText: passwordHint,
                // The rest of the styling (fillColor, border, hintStyle) comes from AppTheme.inputDecorationTheme
              ),
            ),

            const SizedBox(height: 32),

            // Login Button
            SizedBox(
              width: double.infinity,
              height: 52,
              child: ElevatedButton(
                onPressed: isLoading ? null : onLoginPressed,
                // Styling comes from AppTheme.elevatedButtonTheme
                child: isLoading
                    ? const SizedBox(
                        height: 24,
                        width: 24,
                        child: CircularProgressIndicator(
                          color: AppColors.textPrimary,
                          strokeWidth: 3,
                        ),
                      )
                    : Text(
                        buttonText,
                        style: Theme.of(context).elevatedButtonTheme.style?.foregroundColor != null ? Theme.of(context).textTheme.labelLarge?.copyWith(color: Theme.of(context).elevatedButtonTheme.style?.foregroundColor?.resolve({})) : Theme.of(context).textTheme.labelLarge,
                      ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}