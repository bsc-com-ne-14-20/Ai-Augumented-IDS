import 'package:flutter/material.dart';
import '../theming/app_colors.dart';

class IdsLogo extends StatelessWidget {
  final double size;

  const IdsLogo({
    super.key,
    this.size = 80,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: const BoxDecoration(
        color: AppColors.primaryBlue, 
        shape: BoxShape.circle,
      ),
      child: Center(
        child: Icon(
          Icons.shield,           // Shield icon 
          size: size * 0.55,
          color: AppColors.textPrimary,
        ),
      ),
    );
  }
}