import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

@Component({
  selector: 'app-login-callback',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './login-callback.html',
  styleUrl: './login-callback.css',
})
export class LoginCallback implements OnInit{

  constructor(
    private route: ActivatedRoute,
    private router: Router,
  ) {}

  // manageFriend() {
  //   this.router.navigate(['/manage-friends']);
  // }

  ngOnInit(): void {
    const tokenFromUrl = this.route.snapshot.queryParamMap.get('token');
    const tokenFromStorage = localStorage.getItem('jwt');

    if (tokenFromUrl) {
      localStorage.setItem('jwt', tokenFromUrl);
      console.log('JWT zapisany z URL');
    }

    if (!tokenFromUrl && !tokenFromStorage) {
      console.error('Brak tokena – użytkownik niezalogowany');
      return;
    }
  }
}
