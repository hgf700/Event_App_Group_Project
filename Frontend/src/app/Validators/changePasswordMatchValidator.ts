import { AbstractControl, ValidationErrors, ValidatorFn } from '@angular/forms';

export const changePasswordMatchValidator: ValidatorFn = (control: AbstractControl): ValidationErrors | null => {
  const Password = control.get('newPassword')?.value;
  const RepeatPassword = control.get('repeatNewPassword')?.value;

  if (!Password || !RepeatPassword) return null;

  return Password === RepeatPassword
    ? null
    : { passwordMismatch: true };
};