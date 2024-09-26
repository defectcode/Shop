import { IsString } from 'class-validator'

export class CreateStoreDto {
	@IsString({
		message: 'Name is required'
	})
	title: string
}
