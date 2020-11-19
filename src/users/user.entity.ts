export class Pet {

  constructor(name: string, picId: number) {
    this.name = name;
    this.picId = picId;
  }

  name: string;
  picId: number;
}

export class User {

  constructor(username: string, password: string, pet: Pet) {
    this.username = username;
    this.password = password;
    this.pet = pet;
  }

  username: string;
  password: string;
  pet: Pet;
}