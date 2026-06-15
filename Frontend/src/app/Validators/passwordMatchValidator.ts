import { AbstractControl, ValidationErrors, ValidatorFn } from '@angular/forms';

export const passwordMatchValidator: ValidatorFn = (control: AbstractControl): ValidationErrors | null => {
  const newPassword = control.get('newPassword')?.value;
  const repeatNewPassword = control.get('repeatNewPassword')?.value;

  if (!newPassword || !repeatNewPassword) return null;

  return newPassword === repeatNewPassword
    ? null
    : { passwordMismatch: true };
};