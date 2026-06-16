import { AbstractControl, ValidationErrors, ValidatorFn } from '@angular/forms';

export const registerPasswordMatchValidator: ValidatorFn = (control: AbstractControl): ValidationErrors | null => {
  const Password = control.get('password')?.value;
  const RepeatPassword = control.get('confirmPassword')?.value;

  if (!Password || !RepeatPassword) return null;

  return Password === RepeatPassword
    ? null
    : { passwordMismatch: true };
};