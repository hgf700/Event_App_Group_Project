import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { SeedService } from '../../Services/SeedService'

@Component({
  selector: 'app-seed-data',
  imports: [CommonModule, RouterModule],
  templateUrl: './seed-data.html',
  styleUrl: './seed-data.css',
})
export class SeedData implements OnInit {

  constructor(
    private seedService: SeedService,
  ) {}

  ngOnInit(): void {
    this.seedDataBase();
  }

  seedDataBase() {
    this.seedService.seedDataBase().subscribe({
      next: (data) => {
        console.log('seedDataBase')
      },
      error: (err) => {
        console.error(err);
        alert('Nie udało się seedDataBase');
      },
    });
  }

}
